#!/usr/bin/env python3

""" import json files from NIST NVD into a database
     
    history:
        o v0.5 - created database loader, sent project on to github
        o v0.6 - store history of loading in the database, use that history so that all data is not reloaded unless we suspect that we are out of date. Fixed database initialization so it will work if we have a valid config.json 
        listed in the source.
        o v0.6.1 - added index so database is compatable with falco 3rd party code security app
        o v0.6.2 - began to change database modeling for CPE to be able to use cpe's instead of vulnerable_software_list
        o v0.6.3 - updated to support NIST NVD v1.1 JSON data

    (c)Mark Menkhus 2019-2022 mark.menkhus@gmail.com

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

"""


import requests
import json
import re
import zipfile
import mysql.connector
import os
import sys
import datetime
import syslog


__author__ = 'Mark Menkhus, mark.menkhus@gmail.com'
__version__ = '0.6.3'
__DEBUG__ = False


def get_file_lastModifiedDate(file_url):
    """ get the modified date and meta data for a file on the nist site using the .meta file

        example:
        lastModifiedDate:2019-10-12T20:07:56-04:00
        size:32169411
        zipSize:1840270
        gzSize:1840126
        sha256:64310FE691D08F3BCACAA566249195447543A0AA5F3E61CB5FB6F29DC2C9A06F
    """
    url = file_url.replace('json.zip','meta')
    metadata = requests.get(url).text
    metadata = metadata.split('\n')
    lastModifiedDate = metadata[0].lstrip('lastModifiedDate:').rstrip('\r')
    size = metadata[1].lstrip('size:').rstrip('\r')
    zipSize = metadata[2].lstrip('zipSize:').rstrip('\r')
    gzSize = metadata[3].lstrip('gzSize:').rstrip('\r')
    sha256 = metadata[4].lstrip('sha256:').rstrip('\r')
    return (lastModifiedDate,size,zipSize, gzSize,sha256)


def download_if_lastdownloaded_lt_lastModifiedDate(usr, password, db, url):
    """ decide if the lastModifiedDate on the NVD meta file is newer or the same as what we
        stored the last time we udpated the database
    """
    lastModifiedDate = get_file_lastModifiedDate(url)[0]
    sql = 'select lastModifiedDate from update_history where download_name = %s order by downloadedDate desc limit 1;'
    conn = mysql.connector.connect(
        host = "127.0.0.1",
        user = usr,
        passwd = password,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True,
        database=db
    )
    curs = conn.cursor()
    curs.execute(sql,(url,))
    try:
        previouslastModifiedDate = str(curs.fetchone()[0])
    except:
        # if no data in the database then 
        # pick some date that will be in the past and make that the date for comparison
        previouslastModifiedDate = '2019-00-01T00:00:00-04:00'
    try:
        if lastModifiedDate > previouslastModifiedDate:
            return True
        else:
            return False
    
    except Exception as oops:
        print(oops)
        print('non critical error - download_if_lastdownloaded_lt_lastModifiedDate url: %s previous date: %s last date: %s' % (url,previouslastModifiedDate, lastModifiedDate))
        return False


def get_from_nist(url,destinationfile):
    """ copy the file from NIST NVD site
    """
    print('Downloading %s' % destinationfile) 
    data = requests.get(url)
    with open(destinationfile, 'wb') as f: 
        f.write(data.content)
    
    return True
 
 
def unzip(filename):
    """ unzip a file 
    """
    try:
        with zipfile.ZipFile(filename,"r") as zip_ref:
            zip_ref.extractall(os.path.dirname(filename))
    except Exception as oops:
        print("nvdjsonloader.py.unzip: %s, %s" % (oops, filename))
        return False
    
    return True
 
 
def initial_setup(get_all_data=False):
    """ setup constants

        database configuration not stored in the code keep it in config.json each key is 
        about this project, but in general, dbname, path, dbserver, dba (database admin), password
        sqlite does not have a password, but I set these up for all my database projects.

        There are constants like where is the NVD site, what is the file name format.
    """
    # setup to work with configs on my laptop or my home machine
    # the config.json has dbname, dba, password, and could have host bt this 
    # is currently set to localhost
    try:
        configfile = '/Users/menkhus/.nvd_db/config.json'
        myconfig = json.loads(open(configfile).read())
    except FileNotFoundError:
        # make this a read only file in your home dir
        # modify as needed
        configfile = '/Users/a_user_name/.nvd_db/config.json.template'
        myconfig = json.loads(open(configfile).read())
    db = myconfig['dbname']
    user = myconfig['dba']
    password = myconfig['password']
    thisyear = datetime.datetime.now()
    thisyear = thisyear.year
    filenametemplate = './jsonfiles/nvdcve-1.1-year.json'
    if not os.path.exists('./jsonfiles'):
        os.makedirs('./jsonfiles')
    if get_all_data:
        # the 2002 file is the first file, but CVEs go back earlier than 2002
        modifiers = list(range(2002,thisyear+1))
        modifiers.append('modified')
        modifiers.append('recent')
    else:
        modifiers=['modified','recent']
    # NVD changes the version in the path, and the version of the schema's used
    # watch for this to change.  Most recent change was fall 2019
    baseurl = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-year.json.zip'
    
    return (modifiers,filenametemplate,thisyear,db, user, password, baseurl)


def get_vulnerable_software_list(config):
    """ input: is the python dictionary structure from the nvd's JSON input for the CVE item,
        it has 'and' 'or' logic.  We are just going to use the 'or' logic to start.  Will create a more or less simplified version of the more complex configuration structure
        return a list of cpe items.

        Use this to make simple queries about configurations which are impacted.  This is a full text 
        column, and you ask for a cpe or a part of a cpe to find CPE entries that are impacted 
        company:product:version

        I did this to make cpe specific searches directly possible
    """
    vulnerable_software_list = []
    for node in config['nodes']:
        for cpes in node.keys():
            try:
                for cpe in node[cpes]:
                    if type(cpe) == dict and cpe['vulnerable'] == True:
                        vulnerable_software_list.append(cpe['cpe23Uri'])
            except Exception as oops:
                # print("vulnerable_software_list: %s on finding cpe in config['nodes']" % (oops,))
                pass

    return ','.join(vulnerable_software_list)


def get_data(cve):
    """ these are some of the data items that we can depend to be there
        input is a dict of a particular CVE data pulled from NIST

        There are a few data items that may not be there initially, namely
        the CVSS v2, CVSS v3, scoring, CPE items from impacts.
        Over time we expect the CVE data to be filled in.

        get CVSS stuff too:
        {
        'version': '2.0',
        'vectorString': 'AV:L/AC:H/Au:N/C:P/I:N/A:N',
        x'accessVector': 'LOCAL',
        x'accessComplexity': 'HIGH',
        x'authentication': 'NONE',
        x'confidentialityImpact': 'PARTIAL',
        x'integrityImpact': 'NONE',
        x'availabilityImpact': 'NONE',
        x'baseScore': 1.2
        }

    """
    cve_json = str(json.dumps(cve))
    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
    published_date = cve['publishedDate']
    modified_date = cve['lastModifiedDate']
    description = ''
    for blob in cve['cve']['description']['description_data']:
        description += blob['value']
    try:
        configuration = json.dumps(cve['configurations'])
    except:
        configuration = ''
    try:
        if configuration != '':
            vulnerable_software_list = get_vulnerable_software_list(cve['configurations'])
        else:
            vulnerable_software_list = []
    except:
        vulnerable_software_list = []
    try:
        impact = cve['impact']['baseMetricV2']['cvssV2']['baseScore']
    except:
        impact = 0.0
    try:
        ref = cve['cve']['references']['reference_data']
        references = []
        for item in ref:
            references.append(item['url'])
        references = ','.join(references)
    except:
        references = ''
    try:
        vector = cve['impact']['baseMetricV2']['cvssV2']['accessVector']
    except:
        vector = ''
    try:
        access_complexity = cve['impact']['baseMetricV2']['cvssV2']['accessComplexity']
    except:
        access_complexity = ''
    try:
        authorize = cve['impact']['baseMetricV2']['cvssV2']['authentication']
    except:
        authorize = ''
    try:
        confidentiality_impact = cve['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
    except:
        confidentiality_impact = ''
    try:
        availability_impact = cve['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
    except:
        availability_impact = ''
    try:
        integrity_impact = cve['impact']['baseMetricV2']['cvssV2']['integrityImpact']
    except:
        integrity_impact = ''
    return (cve_id,description,configuration,vulnerable_software_list,impact,vector,access_complexity, authorize,confidentiality_impact,integrity_impact,availability_impact, published_date,modified_date,references,cve_json)


def setup_database(db,usr,password):
    """ create database, table & index to store NVD data in
    """
    db_schema = """CREATE DATABASE IF NOT EXISTS nvd  
                    DEFAULT CHARACTER SET='utf8mb4' 
                    DEFAULT COLLATE='utf8mb4_unicode_ci';
                """

    nvd_schema = """-- nvd is a database in progress to pull CVE data from the NIST JSON tables
    --
    CREATE TABLE if not exists nvd (
    -- our sql representation of the NIST NVD data
        id int not NULL auto_increment,
        cve_id varchar(20),
        summary mediumtext,
        config mediumtext,
        score real(3,1),
        access_vector varchar(16),
        access_complexity varchar(16),
        authorize varchar(32),
        availability_impact varchar(8),
        confidentiality_impact varchar(8),
        integrity_impact varchar(8),
        last_modified_datetime varchar(64),
        published_datetime varchar(64),
        urls mediumtext,
        vulnerable_software_list mediumtext,
        primary key (id)
    );
    # this table does not have to be filled, but it seemed important
    # to have the source information to be able to add new features as
    # time permits
    """
    nvd_json_schema = """
    -- nvd_json is the whole of the JSON from NVD stored by CVE ID
    CREATE TABLE if not exists nvd_json (
        id int not NULL auto_increment,
        cve_id varchar(20),
        cve_item json,
        primary key (id)
    );
    """
    update_history_schema = """--
    create table if not exists update_history (
        -- this is the collection of download records for different files that NIST supplies.
        id int not NULL auto_increment,
        download_name text,
        lastModifiedDate varchar(80),
        downloadedDate varchar(80),
        size int,
        zipSize int,
        gzSize int,
        sha256 text,
        primary key(id)
    );
    """
    nvd_cpe = """
    create table if not exists nvd_cpe (
        id int not null auto_increment,
        nvd_id int not null references nvd,
        cpe_id  int not null references cpe,
        primary key(id)
    );
    """
    cpe = """CREATE TABLE IF NOT EXISTS cpe(
        -- cpe:2.3:o:bsdi:bsd_os:3.1:*:*:*:*:*:*:*
        id int not NULL auto_increment,
        cpe_version_id int,
        cpe_type_id int,
        software_version_id int not null references software_version,
        primary key (id)
    );
    """
    software_version = """CREATE TABLE IF NOT EXISTS software_version(
        id int not NULL auto_increment,
        vers text,
        subvers text,
        software_product_id int not null references software_product,
        primary key (id)
    );
    """
    software_product = """CREATE TABLE IF NOT EXISTS software_product(
        id int not NULL auto_increment,
        product text,
        software_vendor_id int not null references software_vendor,
        primary key (id)    
    );
    """
    software_vendor = """CREATE TABLE IF NOT EXISTS software_vendor(
        id int not NULL auto_increment,
        vendor text,
        primary key (id)    
    );
    """
    # add tables here, implement them in the insert_data_into_db and 
    # get_data(cve)
    # dive into the data and have fun!
    conn = mysql.connector.connect(
        host = "127.0.0.1",
        user = usr,
        passwd = password,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True
        )
    curs = conn.cursor()
    curs.execute(db_schema)
    conn.commit()
    conn.close()
    conn = mysql.connector.connect(
        host = "127.0.0.1",
        user = usr,
        passwd = password,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        use_unicode=True,
        database = db
        )
    curs = conn.cursor()
    curs.execute(nvd_schema)
    curs.execute(nvd_json_schema)
    curs.execute(update_history_schema)
    curs.execute(nvd_cpe)
    curs.execute(cpe)
    curs.execute(software_version)
    curs.execute(software_product)
    curs.execute(software_vendor)
    try:
        curs.execute('create index dates on nvd(published_datetime);')
        curs.execute('alter table nvd add fulltext(vulnerable_software_list);')
        curs.execute('create index ix_cve on nvd(cve_id);')
        curs.execute('create index ix_cve_json on nvd_json(cve_id);')
        curs.execute('ALTER TABLE nvd CONVERT TO CHARACTER SET utf8;')
    except:
        pass
    conn.commit()
    conn.close()


def insert_data_into_db(db,usr,password,data,source_url):
    """ 
    insert the data into the database, we pulled it as json, and we do store all the json data 
    in nvd_json table.

    We are still learning the JSON material so right now, this data saves most of the CVE data TWICE into the database.  We save the json data into cve_item which is doubling the data. Note, cve_item is pretty much the original CVE JSON, 
    and we use that to learn more about the format of the data.
    """
    try:
        conn = mysql.connector.connect(
            host = "127.0.0.1",
            user = usr,
            passwd = password,charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            use_unicode=True,
            database = db
            )
    except Exception as oops:
        print('no database yet - setting up database: %s' % db)
    conn = mysql.connector.connect(
            host = "127.0.0.1",
            user = usr,
            passwd = password,charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            use_unicode=True,
            database = db
        )
    curs = conn.cursor(buffered=True)
    download_date = datetime.datetime.now().isoformat()
    lastModifiedDate,size,zipSize,gzSize,sha256 = get_file_lastModifiedDate(source_url)
    sql = "insert into update_history(download_name,downloadedDate,lastModifiedDate,size,zipSize,gzSize,sha256) values (%s,%s,%s,%s,%s,%s,%s);"
    try:
        curs.execute(sql,(source_url,download_date,lastModifiedDate,size,zipSize, gzSize,sha256))
    except Exception as oops:
        print(oops)
        print('insert_date_into_db: sql: %s' % sql)
        print("%s %s %s %s %d=s %s %s" % (source_url,download_date,lastModifiedDate,size,zipSize, gzSize,sha256))
    cvecount = 0
    replace_sql = r'replace into nvd(id, cve_id, summary, config, vulnerable_software_list, score, access_vector, access_complexity, authorize, confidentiality_impact,integrity_impact,availability_impact, published_datetime, last_modified_datetime, urls) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);'
    insert_sql = r'insert into nvd(cve_id, summary, config, vulnerable_software_list, score, access_vector, access_complexity, authorize, confidentiality_impact,integrity_impact,availability_impact, published_datetime, last_modified_datetime, urls) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);'
    sql_for_json = r'replace into nvd_json(cve_id, cve_item) values(%s,%s);'
    for cve in data['CVE_Items']:
        cvecount += 1
        cve_id,description,configuration,vulnerable_software_list,impact,vector,access_complexity,authorize,confidentiality_impact,integrity_impact,availability_impact,published_date,modified_date,references,cve_json = get_data(cve)
        try:
            curs.execute('select id from nvd where cve_id = %s limit 1;',(cve_id,))
            cur_id = curs.fetchone()
            if cur_id == None:
                curs.execute(insert_sql,(cve_id, description,configuration,vulnerable_software_list,impact,vector,access_complexity,authorize,confidentiality_impact,integrity_impact,availability_impact,published_date,modified_date,references))
                conn.commit()
            # print("current id: %s cve_id: %s" % (cur_id,cve_id))
            else:
                curs.execute(replace_sql,(cur_id[0], cve_id, description,configuration,vulnerable_software_list,impact,vector,access_complexity,authorize,confidentiality_impact,integrity_impact,availability_impact,published_date,modified_date,references))
                conn.commit()
        except Exception as oops:
            print('insert_data_into_db: %s, while getting id.' % (oops,))
            print('if you get an error reting to insert unicode, try this: ALTER TABLE nvd.nvd CONVERT TO CHARACTER SET utf8;')
            exit()

        """     except Exception as oops:
            print('data error: %s\ndata: %s\ncve_id: %s\n,description: %s\n,configuration: %s\n,vulnerable_software_list: %s\n,impact: %s\naccess_complexity: %s\n,authorize: %s\n,confidentiality_impact: %s\n,integrity_impact: %s\n,availability_impact: %s\n,published_date: %s\n,modified_date: %s\n,references: %s\n' % (oops,cve,cve_id,description,configuration,vulnerable_software_list,impact,access_complexity,authorize,confidentiality_impact,integrity_impact,availability_impact,published_date,modified_date,references))
            exit()
        """
        try:
            curs.execute('select id from nvd_json where cve_id = %s limit 1;',(cve_id,))
            cur_id = curs.fetchone()
            if cur_id == None:
                curs.execute(r'insert into nvd_json(cve_id, cve_item) values(%s,%s);', (cve_id,cve_json))
                conn.commit()
            else:
                curs.execute(r'replace into nvd_json(id, cve_id, cve_item) values(%s, %s,%s);', (cur_id[0], cve_id,cve_json))
                conn.commit()
        except Exception as oops:
            print('data error: %s\ncve_id: %s\njson data: %s' % (oops, cve_id, cve_json))
            exit()
    conn.commit()
    conn.close()
    
    return cvecount


def cve_tally(db,user,password):
    """ what are the total number of CVEs in the database?"""
    sql = "select count(distinct(cve_id)) from nvd;"
    conn = mysql.connector.connect(
            host = "127.0.0.1",
            user = user,
            passwd = password,charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            use_unicode=True,
            database = db
        )
    curs = conn.cursor(buffered=True)
    curs.execute(sql,)
    count = curs.fetchone()[0]
    return count    

def get_and_load(modifiers,filenametemplate,thisyear,db,user,password,baseurl):
    """  using a base url and filename, request data from the nist website,
        unzip that data, pull the JSON into a pythond dict in UTF-8 format and
        then save each CVE item into the database.

        There are cves from 2002 to present year, a modified file and recent file,
        so one file per year,plus these two are pulled and loaded.
    """
    cvecount = 0
    for modifier in modifiers:
        modifier = str(modifier)
        filename = re.sub('year', modifier, filenametemplate)
        url = re.sub('year', modifier, baseurl)
        if download_if_lastdownloaded_lt_lastModifiedDate(user, password, db, url):
            get_from_nist(url,filename+'.zip')
            unzip(filename+'.zip')
            data = json.loads((open(filename,encoding="utf8").read()))
            cvecount += insert_data_into_db(db,user,password,data,url)
            print("loaded %s file from NIST into %s database" % (filename, db))
            syslog.syslog(syslog.LOG_NOTICE,"nvd2mysqlloader.py: loaded %s file from NIST into %s database" % (filename, db))
            os.remove(filename)
            os.remove(filename +'.zip')

    return cvecount


def cli():
    argc = len(sys.argv) - 1
    cmd = os.path.basename(sys.argv[0])
    helptext = """ \n%s is a program to load a database with the NIST NVD CVE data.

    Default behavior is to refresh the data with just the latest info.

    -h gives this help text
    -a loads all the CVE data from 2002 to present. 
    """
    if argc == 1:
        if sys.argv[1] == '-a':
            return True
        if sys.argv[1] == '-h':
            print(helptext.lstrip(' ') % cmd)
            exit()
    else:
        return False
        
 
def main():
    """  
        load the NIST NVD data into a SQL database.

    """
    get_all_data = cli()
    modifiers,filenametemplate,thisyear,db,user,password,baseurl = initial_setup(get_all_data)
    setup_database(db,user,password)
    syslog.openlog(logoption=syslog.LOG_PID)
    syslog.syslog(syslog.LOG_NOTICE,'nvd2mysqlloader.py: started')
    cve_tally_before = cve_tally(db,user,password)
    loadcount = get_and_load(modifiers,filenametemplate,thisyear,db,user,password,baseurl)
    cve_tally_after = cve_tally(db,user,password)
    added_cves = cve_tally_after - cve_tally_before
    if loadcount == 0:
        syslog.syslog(syslog.LOG_NOTICE,"nvd2mysqlloader.py: There were no new CVEs added since last update.")
        print("nvd2mysqlloader.py: There were no new CVEs added since last update.")
    else:    
        syslog.syslog(syslog.LOG_NOTICE,"nvd2mysqlloader.py: There were %s CVEs loaded or updated." % loadcount)
        print("nvd2mysqlloader.py: There were %s CVEs loaded or updated with %s CVEs added." % (loadcount,added_cves))


if __name__ == '__main__':
    main()
