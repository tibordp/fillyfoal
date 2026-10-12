CREATE DATABASE shop;
USE shop;
CREATE TABLE stock (
  id INT NOT NULL PRIMARY KEY,
  name VARCHAR(40) NOT NULL,
  qty INT NULL,
  note TEXT NULL,
  KEY by_name (name)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=1;
INSERT INTO stock
SELECT i, CONCAT('item-', LPAD(i, 4, '0')), IF(i % 7 = 0, NULL, i * 3),
  IF(i % 20 = 0, REPEAT(CONCAT('long note ', i, ' '), 80), IF(i % 3 = 0, CONCAT('note ', i), NULL))
FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40) SELECT i FROM n) AS n;
DELETE FROM stock WHERE id % 11 = 0;
UPDATE stock SET name = CONCAT(name, '-x') WHERE id % 13 = 0;
INSERT INTO stock VALUES (1000, 'late', 1, 'added after the deletes');
