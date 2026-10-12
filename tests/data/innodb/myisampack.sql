CREATE DATABASE shop;
USE shop;
CREATE TABLE crate (
  id INT NOT NULL,
  label CHAR(12) NOT NULL,
  note VARCHAR(30) NULL,
  colour ENUM('red', 'green', 'blue') NOT NULL,
  kind CHAR(4) NOT NULL DEFAULT 'box',
  weight INT NULL,
  packed DATE NULL
) ENGINE=MyISAM;
INSERT INTO crate
SELECT i, CONCAT('crate ', i), IF(i % 4 = 0, NULL, CONCAT('note ', REPEAT('x', i % 9))),
  ELT(1 + i % 3, 'red', 'green', 'blue'), 'box', IF(i % 5 = 0, NULL, i * 100),
  IF(i % 6 = 0, NULL, DATE_ADD('2024-01-01', INTERVAL i DAY))
FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 24) SELECT i FROM n) AS n;
CREATE TABLE memo (id INT NOT NULL, body TEXT NULL) ENGINE=MyISAM;
INSERT INTO memo VALUES (1, 'short'), (2, NULL), (3, REPEAT('long text ', 40)), (4, 'short');
