-- This schema is supposed to be the same as what is in the code and used by the program.
-- 
-- nvd2mysqlloader.py database setup.
-- Create a database for the NIST CVE data
--
-- Created to be loaded by the nvd2mysqlloader.py . Database can be used by whatever program 
-- wants this data
--
-- Author Mark Menkhus, 2019
--
-- 
--  Copyright 2019 Mark Menkhus
--
--  Licensed under the Apache License, Version 2.0 (the "License");
--  you may not use this file except in compliance with the License.
--  You may obtain a copy of the License at
--  
--     http://www.apache.org/licenses/LICENSE-2.0
--  
--  Unless required by applicable law or agreed to in writing, software
--  distributed under the License is distributed on an "AS IS" BASIS,
--  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--  See the License for the specific language governing permissions and
--  limitations under the License.
--
--
CREATE DATABASE IF NOT EXISTS nvd  
    DEFAULT CHARACTER SET='utf8mb4' 
    DEFAULT COLLATE='utf8mb4_unicode_ci';
--
--
CREATE TABLE if not exists nvd (
    -- our sql representation of the NIST NVD data
    cve_id varchar(16),
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
--
--
create index dates on nvd(published_datetime);
--
--
create table if not exists update_history (
    -- this is the collection of download records for different files that NIST supplies.
    update_id int not NULL auto_increment,
    download_name text,
    lastModifiedDate varchar(80),
    downloadedDate varchar(80),
    size int,
    zipSize int,
    gzSize int,
    sha256 text,
    primary key(update_id)
);