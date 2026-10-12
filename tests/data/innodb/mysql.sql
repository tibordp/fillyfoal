CREATE DATABASE shop;
USE shop;
CREATE TABLE fruit (
  id INT NOT NULL PRIMARY KEY,
  name VARCHAR(32) NOT NULL,
  price DECIMAL(6,2) NULL,
  stock SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  note TEXT NULL,
  KEY by_name (name)
) ENGINE=InnoDB;
INSERT INTO fruit VALUES
 (1,'apple',0.50,120,NULL),(2,'banana',0.25,300,'ripe'),(3,'cherry',4.00,15,NULL),
 (4,'damson',2.10,0,'out of season'),(5,'elderberry',NULL,42,NULL),(6,'fig',1.75,8,'dried'),
 (7,'grape',3.20,64,NULL),(8,'huckleberry',5.00,3,NULL);
DELETE FROM fruit WHERE id = 6;
CREATE TABLE notes (k INT NOT NULL PRIMARY KEY, body TEXT) ENGINE=InnoDB ROW_FORMAT=REDUNDANT;
INSERT INTO notes VALUES (1,'first'),(2,REPEAT('long note ',2000));
CREATE TABLE legacy (id INT NOT NULL PRIMARY KEY, name VARCHAR(20), qty INT) ENGINE=MyISAM;
INSERT INTO legacy VALUES (1,'alpha',10),(2,'beta',NULL),(3,'gamma',30);
CREATE TABLE fixed (id INT NOT NULL, code CHAR(4) NOT NULL) ENGINE=MyISAM ROW_FORMAT=FIXED;
INSERT INTO fixed VALUES (1,'abcd'),(2,'efgh');
DELETE FROM fixed WHERE id=1;
