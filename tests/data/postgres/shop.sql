CREATE DATABASE shop;
\c shop
CREATE TABLE fruit (id int PRIMARY KEY, name text NOT NULL, price numeric(6,2), stock smallint NOT NULL DEFAULT 0, note text);
INSERT INTO fruit VALUES (1,'apple',0.50,120,NULL),(2,'banana',0.25,300,'ripe'),(3,'cherry',4.00,15,NULL),
 (4,'damson',2.10,0,'out of season'),(5,'elderberry',NULL,42,NULL),(6,'fig',1.75,8,'dried'),(7,'grape',3.20,64,NULL),(8,'huckleberry',5.00,3,repeat('long note ', 400));
UPDATE fruit SET stock = 7 WHERE id = 6;
DELETE FROM fruit WHERE id = 3;
VACUUM fruit;
CHECKPOINT;
-- A WAL segment with a little traffic: switch to a fresh segment, make
-- some changes, switch again.
SELECT pg_switch_wal();
CREATE TABLE crate (id int PRIMARY KEY, label text);
INSERT INTO crate VALUES (1,'small'),(2,'medium'),(3,'large');
UPDATE crate SET label = 'huge' WHERE id = 3;
DELETE FROM crate WHERE id = 2;
CHECKPOINT;
\pset tuples_only on
\pset format unaligned
\o /tmp/names
SELECT pg_relation_filepath('fruit');
SELECT pg_relation_filepath('fruit_pkey');
SELECT pg_walfile_name(pg_current_wal_lsn());
\o
SELECT pg_switch_wal();
