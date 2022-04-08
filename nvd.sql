-- This schema is supposed to be the same as what is in the code and used by the program.
-- 
-- nvd2mysqlloader.py database setup.
-- Create a database for the NIST CVE data
--
-- Created to be loaded by the nvd2mysqlloader.py . Database can be used by whatever program 
-- wants this data
--
-- Author Mark Menkhus
--
-- 
--  Copyright 2019-2022 Mark Menkhus
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
USE NVD;
--
-- Bug: the CVSS score is from persepctive of vserion 3.0, current use is 
-- CVSS 3.1 Also, the scope field is missing
-- rename the table fields accordingly, add scope
-- ref: https://www.first.org/cvss/v3-1/cvss-v31-specification_r1.pdf
--  MM March, 16 2022
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
-- 
--  
CREATE TABLE if not exists nvd_json (
    id int not NULL auto_increment,
    cve_id varchar(20),
    cve_item json,
    primary key (id)
);
--
--
create index ix_dates on nvd(published_datetime);
alter table nvd add fulltext(vulnerable_software_list);
create index ix_cve on nvd(cve_id);
create index ix_cve_json on nvd_json(cve_id);
--
--
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
--
--
create table if not exists guess_history (
    -- this is the collection of cvss guessing records for CVEs that we tried to guess.  
    id int not NULL auto_increment,
    cve_id varchar(20),
    guessDate varchar(80),
    primary key(id)
); 
-- 
-- CVE to CPE map
CREATE TABLE IF NOT EXISTS cve2cpe(
    id int not NULL auto_increment,
    primary key(id),
    cve_id int,
    cpe_id int
);
-- 
-- Unique CPE id
CREATE TABLE IF NOT EXISTS CPE(
    id int not NULL auto_increment,
    primary key(id),
    cpe text
    -- CONSTRAINT constraint_name UNIQUE (cpe)
);
-- 
-- Unique CPE vendor
CREATE TABLE IF NOT EXISTS cpe_vendor(
    id int not NULL auto_increment,
    primary key(id),
    vendor text
);
-- 
-- Unique CPE product name
CREATE TABLE IF NOT EXISTS cpe_prod(
    id int not NULL auto_increment,
    primary key(id),
    product text
);
--
-- Unique cpe version string
CREATE TABLE IF NOT EXISTS cpe_version(
    id int not NULL auto_increment,
    primary key(id),
    version text
);