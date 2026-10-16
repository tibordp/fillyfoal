-- Neutral DDL and DML for the mysql-binlog fixtures (see make.sh). Every
-- statement runs at a fixed session time, so event timestamps after the
-- format description are the same on every run.
SET TIMESTAMP = 1767225600;
CREATE DATABASE shop;
USE shop;
CREATE TABLE items (
  id INT PRIMARY KEY,
  tiny TINYINT,
  small SMALLINT UNSIGNED,
  medium MEDIUMINT,
  big BIGINT,
  price DECIMAL(10,2),
  weight FLOAT,
  ratio DOUBLE,
  name VARCHAR(40),
  code CHAR(4),
  note TEXT,
  raw BLOB,
  added DATE,
  at_time TIME(3),
  stamp DATETIME(6),
  changed TIMESTAMP(0) NULL,
  made YEAR,
  colour ENUM('red', 'green', 'blue'),
  flags SET('a', 'b', 'c'),
  bits BIT(10),
  extra JSON
);
SET TIMESTAMP = 1767225660;
INSERT INTO items VALUES
  (1, -5, 65000, -100000, 1234567890123, 12.50, 1.5, 2.25, 'teapot', 'TP01',
   'a ceramic teapot', X'00010203', '2026-01-02', '12:34:56.789',
   '2026-01-02 03:04:05.678901', '2026-01-02 03:04:05', 2026, 'green', 'a,c',
   b'1010101010', '{"colour": "white", "sizes": [1, 2]}'),
  (2, NULL, NULL, NULL, NULL, -0.99, NULL, NULL, 'mug', NULL, NULL, NULL,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
SET TIMESTAMP = 1767225720;
UPDATE items SET price = 13.75, name = 'big teapot' WHERE id = 1;
SET TIMESTAMP = 1767225780;
DELETE FROM items WHERE id = 2;
SET TIMESTAMP = 1767225840;
CREATE TABLE notes (id INT PRIMARY KEY AUTO_INCREMENT, body VARCHAR(100));
SET SESSION binlog_format = 'STATEMENT';
SET TIMESTAMP = 1767225900;
INSERT INTO notes (body) VALUES ('written as a statement');
SET TIMESTAMP = 1767225960;
UPDATE notes SET body = 'still a statement' WHERE id = 1;
SET SESSION binlog_format = 'ROW';
SET TIMESTAMP = 1767226020;
INSERT INTO notes (body) VALUES ('written as a row');
