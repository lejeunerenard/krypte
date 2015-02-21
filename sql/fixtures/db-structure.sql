CREATE TABLE data (
   `sha1_key` varchar(255),
   `value` blob,
   `created_on` datetime,
   `updated_on` datetime,
   PRIMARY KEY (sha1_key)
);
CREATE TABLE users (
   `username` varchar(32),
   `password` varchar(255),
   `user_key` blob,
   `shared_key` blob,
   `is_admin` BOOLEAN NOT NULL DEFAULT 0,
   `created_on` datetime,
   `updated_on` datetime,
   PRIMARY KEY (username)
);
