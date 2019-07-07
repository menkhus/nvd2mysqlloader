#!/usr/bin/env python3
import json
import pprint
import datetime
import re
import sqlite3

thisyear = datetime.datetime.now()
thisyear = thisyear.year
filenametemplate = '/Users/mark/src/nist_cve_json/jsonfiles/nvdcve-1.0-year.json'

modifiers = list(range(2002,thisyear+1))
modifiers[4]
modifiers.append('modified')

conn = sqlite3.connect('nvd_json.sqlite3')
schema = """ create table nvd_json(
id integer primary key autoincrement,
cve_item text
);
"""

sql_example_json_query=" select cve_item from nvd_json where json_extract(cve_item,'$.CVE_data_meta.ID') = 'CVE-1999-0001';"
curs = conn.cursor()

cvelist = []
sql = 'insert into nvd_json(cve_item) values(?)'
for modifier in modifiers:
    modifier = str(modifier)
    filename = re.sub('year', modifier, filenametemplate)
    print(filename)
    data = json.loads((open(filename).read()))
    for cve in data['CVE_Items']:
        cvelist.append(cve)
        try:
            cve = str(json.dumps(cve['cve']))
            curs.execute(sql,(cve,))
        except Exception as oops:
            print('data error: %s\ndata: %s' % (oops,cve))
            exit()
    conn.commit()
conn.close()


print('there are %s items in the list' % len(cvelist))
