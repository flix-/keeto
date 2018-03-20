CREATE TABLE openssh_connect (
session_id BIGINT UNSIGNED NOT NULL,
timestamp DATETIME NOT NULL,
server_addr VARCHAR(255) NOT NULL,
server_port SMALLINT UNSIGNED NOT NULL,
client_addr VARCHAR(255) NOT NULL,
client_port SMALLINT UNSIGNED NOT NULL
);
ALTER TABLE openssh_connect ADD CONSTRAINT pk_openssh_connect PRIMARY KEY (session_id);
ALTER TABLE openssh_connect MODIFY session_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT;

CREATE TABLE keeto_fingerprint (
username VARCHAR(32) NOT NULL,
hash_algo ENUM('MD5', 'SHA256') NOT NULL,
fingerprint VARCHAR(255) NOT NULL
);
ALTER TABLE keeto_fingerprint ADD CONSTRAINT pk_keeto_fingerprint PRIMARY KEY (hash_algo, fingerprint);

CREATE TABLE openssh_auth (
session_id BIGINT UNSIGNED NOT NULL,
auth_id BIGINT UNSIGNED NOT NULL,
timestamp DATETIME NOT NULL,
event ENUM('OPENSSH_AUTH_FAILURE', 'OPENSSH_AUTH_SUCCESS') NOT NULL,
username VARCHAR(32) NOT NULL,
hash_algo ENUM('MD5', 'SHA256') NOT NULL,
fingerprint VARCHAR(255) NOT NULL
);
ALTER TABLE openssh_auth ADD CONSTRAINT pk_openssh_auth PRIMARY KEY (auth_id);
ALTER TABLE openssh_auth MODIFY auth_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT;
ALTER TABLE openssh_auth ADD CONSTRAINT fk_openssh_auth_openssh_connect FOREIGN KEY (session_id) REFERENCES openssh_connect (session_id);

CREATE TABLE openssh_disconnect (
session_id BIGINT UNSIGNED NOT NULL,
timestamp DATETIME NOT NULL
);
ALTER TABLE openssh_disconnect ADD CONSTRAINT pk_openssh_disconnect PRIMARY KEY (session_id, timestamp);
ALTER TABLE openssh_disconnect ADD CONSTRAINT fk_openssh_disconnect_openssh_connect FOREIGN KEY (session_id) REFERENCES openssh_connect (session_id);

