CREATE DATABASE shop;
USE shop;
CREATE TABLE crate (
  id INT UNSIGNED NOT NULL PRIMARY KEY,
  label CHAR(6) CHARACTER SET latin1 NOT NULL,
  colour ENUM('red','green','blue') NULL,
  packed DATE NULL,
  seen DATETIME(3) NULL,
  weight FLOAT NULL,
  ratio DOUBLE NULL,
  delta BIGINT NOT NULL,
  flags SET('fragile','heavy','cold') NOT NULL DEFAULT ''
) ENGINE=InnoDB;
INSERT INTO crate VALUES
 (1,'small','red','2024-02-29','2024-02-29 12:34:56.789',1.5,0.25,-42,'fragile'),
 (2,'medium',NULL,NULL,NULL,NULL,NULL,9000000000,'heavy,cold'),
 (3,'large','blue','1999-12-31','2000-01-01 00:00:00.001',12.25,-3.5,0,'');
