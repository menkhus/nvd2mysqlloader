# nvd2mysqlloader.py

* load and update a mysql database with the NIST NVD CVE data.

Author: [Mark Menkhus](mailto:mark.menkhus@gmail.com) 

## nvd2mysqlloader.py Default behavior 

* Refresh the data with just the latest info.

  -h gives this help text  
  -a loads all the CVE data from 2002 to present.

* Currently loads version 1.0 of NIST NVD CVE informations.

&copy;2019-2022, Mark Menkhus
License: [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

## How to use 

* This code works with Mysql server 5.7

* create a database on mysql server called nvd

* create a user and role that will be able to create the tables in nvd, and insert data

* create users who can read the nvd table

### This code is used on mysql 5.7 and with minor modification on version 8.0

