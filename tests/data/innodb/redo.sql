CREATE DATABASE shop;
USE shop;
CREATE TABLE fruit (id INT NOT NULL PRIMARY KEY, name VARCHAR(32) NOT NULL) ENGINE=InnoDB;
INSERT INTO fruit VALUES (1,'apple'),(2,'banana'),(3,'cherry');
UPDATE fruit SET name='blueberry' WHERE id=2;
DELETE FROM fruit WHERE id=3;
