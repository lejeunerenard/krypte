CREATE TABLE data (
   `sha1_key` varchar(255),
   `value` blob,
   `created_on` datetime,
   `updated_on` datetime,
   PRIMARY KEY (sha1_key)
);
