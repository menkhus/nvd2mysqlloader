#!/usr/bin/env python3

""" import json files from NIST NVD into a database
 
    Mark Menkhus 2019 mark.menkhus@hpe.com

    to do:
        o understand that NIST data and pull all the NIST provied data
        o store history of loading in the database, use that history so that all data is not reloaded unless we suspect that we are out of date

    Copyright 2019 Mark Menkhus

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
__version__ = '0.5'
__DEBUG__ = False

 
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
    configfile = '/Users/mark/.nvd_db/config.json'
    myconfig = json.loads(open(configfile).read())
    db = myconfig['dbname']
    user = myconfig['dba']
    password = myconfig['password']
    thisyear = datetime.datetime.now()
    thisyear = thisyear.year
    filenametemplate = './jsonfiles/nvdcve-1.0-year.json'
    if not os.path.exists('./jsonfiles'):
        os.makedirs('./jsonfiles')
    if get_all_data:
        # the 2002 file is the first file, but CVEs go back earlier than 2002
        modifiers = list(range(2002,thisyear+1))
        modifiers.append('modified')
        modifiers.append('recent')
    else:
        modifiers=['modified','recent']
    # NVD has changed the version in the path, and the version of the schema's used
    # watch for this to change!!!
    baseurl = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-year.json.zip'
    
    return (modifiers,filenametemplate,thisyear,db, user, password, baseurl)


def get_vulnerable_software_list(config):
    """ input: is the python dictionary structure from the nvd's JSON input for the CVE item,
        is has 'and' 'or' logic.  We are just going to use the 'or' logic to start.  Will create a more or less simplified version of the more complex configuration structure
        return a list of cpe items.
    """
    vulnerable_software_list = []
    for node in config['nodes']:
        for cpes in node.keys():
            try:
                for cpe in node[cpes]:
                    if type(cpe) == dict and cpe['vulnerable'] == True:
                        vulnerable_software_list.append(cpe['cpe23Uri'])
            except Exception as oops:
                pass
    return ','.join(vulnerable_software_list)

def get_data(cve):
    """ these are some of the data items that we can depend to be there
        input is a dict of a particular CVE data pulled from NIST

        There are a few data items that may not be there initially, namely
        the CVSS v2, CVSS v3, scoring, CPE items from impacts.
        Over time we expect the CVE data to be filled in.

        get this stuff too:
        {
        'version': '2.0',
        'vectorString': 'AV:L/AC:H/Au:N/C:P/I:N/A:N',
        'accessVector': 'LOCAL',
        'accessComplexity': 'HIGH',
        'authentication': 'NONE',
        'confidentialityImpact': 'PARTIAL',
        'integrityImpact': 'NONE',
        'availabilityImpact': 'NONE',
        'baseScore': 1.2
        }

    """
    cve_json = str(json.dumps(cve))
    cve_id = cve["cve"]["CVE_data_meta"]["ID"]
    published_date = cve['publishedDate']
    modified_date = cve['lastModifiedDate']
    description = cve['cve']['description']['description_data'][0]['value']
    try:
        configuration = json.dumps(cve['configurations'])
    except:
        configuration = ''
    try:
        if configuration != '':
            vulnerable_software_list = get_vulnerable_software_list(cve['configurations'])
        else:
            vulnerable_software_list = ''
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
    return (cve_id,description,configuration,vulnerable_software_list,impact,vector, published_date,modified_date,references,cve_json)


def setup_database(db,usr,password):
    """ create database, table & index to store NVD data in
    """
    db_schema = """CREATE DATABASE IF NOT EXISTS nvd  
                    DEFAULT CHARACTER SET='utf8mb4' 
                    DEFAULT COLLATE='utf8mb4_unicode_ci';
                """

    cve_schema = """-- nvd_json is a database in progress to pull CVE data from the NIST JSON tables
    --
    -- when we are reasonably done, we will take the json cve_item out of the table, but it's
    -- there if we need it. 
    --          Mark Menkhus, 2019 mdm@hpe.com
    --
    CREATE TABLE if not exists nvd (cve_id varchar(16),
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
        cve_item mediumtext,
        primary key (cve_id)
    );
    """
    # add columns here, implement them in the insert_data_into_db and 
    # get_data(cve)
    # dive into the data and have fun!
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
    curs.execute(db_schema)
    conn.commit()
    curs.execute(cve_schema)
    conn.commit()
    #curs.execute('create index dates on nvd(published_datetime);')
    #conn.commit()
    conn.close()


def insert_data_into_db(db,usr,password,data):
    """ 
    insert the json data into the database

    We are still learning the JSON material so right now, this data saves most of the CVE data TWICE into the database.  We save 
    into cve_item which is doubling the data. cve_item is the original CVE, and we use that to learn more about the format of the
    data.

    ALTER USER 'mark'@'localhost' IDENTIFIED WITH mysql_native_password BY 'mypasswd';

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
    curs = conn.cursor()
    cvecount = 0
    sql = r'replace into nvd(cve_id, summary, config, vulnerable_software_list, score, access_vector, published_datetime, last_modified_datetime, urls, cve_item) values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);'
    for cve in data['CVE_Items']:
        cvecount += 1
        cve_id,description,configuration,vulnerable_software_list,impact,vector,published_date,modified_date,references,cve_json = get_data(cve)
        try:
            curs.execute(sql,(cve_id,description,configuration,vulnerable_software_list, impact,vector, published_date,modified_date,references,cve_json))
        except Exception as oops:
            print('data error: %s\ndata: %s\ncve_id: %s\n,description: %s\n,configuration: %s\n,vulnerable_software_list: %s\n,impact: %s\n,published_date: %s\n,modified_date: %s\n,references: %s\ncve_json: %s\n' % (oops,cve,cve_id,description,configuration,vulnerable_software_list,impact,published_date,modified_date,references,cve_json))
            exit()
    conn.commit()
    conn.close()
    
    return cvecount


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
        get_from_nist(url,filename+'.zip')
        unzip(filename+'.zip')
        print("loading %s file from NIST into %s database" % (filename, db))
        syslog.syslog(syslog.LOG_NOTICE,"nvd2mysqlloader.py: loading %s file from NIST into %s database" % (filename, db))
        data = json.loads((open(filename,encoding="utf8").read()))
        cvecount += insert_data_into_db(db,user,password,data)
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
    loadcount = get_and_load(modifiers,filenametemplate,thisyear,db,user,password,baseurl)
    syslog.syslog(syslog.LOG_NOTICE,"nvd2mysqlloader.py: There were %s CVEs loaded or updated." % loadcount)
    print("nvd2mysqlloader.py: There were %s CVEs loaded or updated." % loadcount)


if __name__ == '__main__':
    main()
