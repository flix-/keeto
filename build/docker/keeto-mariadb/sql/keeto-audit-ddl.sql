CREATE TABLE openssh_connect (
session_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
timestamp DATETIME NOT NULL,
server_addr TINYTEXT NOT NULL,
client_addr TINYTEXT NOT NULL,
client_port SMALLINT UNSIGNED NOT NULL
);

CREATE TABLE keeto_fingerprint (
username TINYTEXT NOT NULL,
hash_algo ENUM('MD5', 'SHA256') NOT NULL,
fingerprint TINYTEXT NOT NULL
);

CREATE TABLE openssh_auth (
session_id BIGINT UNSIGNED NOT NULL,
timestamp DATETIME NOT NULL,
event ENUM('OPENSSH_AUTH_FAILURE', 'OPENSSH_AUTH_SUCCESS') NOT NULL,
username TINYTEXT NOT NULL,
hash_algo ENUM('MD5', 'SHA256') NOT NULL,
fingerprint TINYTEXT NOT NULL,
CONSTRAINT FOREIGN KEY(session_id) REFERENCES openssh_connect(session_id)
);

CREATE TABLE openssh_disconnect (
session_id BIGINT UNSIGNED NOT NULL,
timestamp DATETIME NOT NULL,
CONSTRAINT FOREIGN KEY(session_id) REFERENCES openssh_connect(session_id)
);

