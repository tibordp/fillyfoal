USE model;
DBCC SHRINKFILE (modeldev, 1) WITH NO_INFOMSGS;
DBCC SHRINKFILE (modellog, 1) WITH NO_INFOMSGS;
GO
CREATE DATABASE shop
 ON PRIMARY (NAME = shop_data, FILENAME = '/var/opt/mssql/data/shop.mdf', SIZE = 3MB, FILEGROWTH = 1MB),
 FILEGROUP extra (NAME = shop_extra, FILENAME = '/var/opt/mssql/data/shop_extra.ndf', SIZE = 1MB, FILEGROWTH = 1MB)
 LOG ON (NAME = shop_log, FILENAME = '/var/opt/mssql/data/shop_log.ldf', SIZE = 1MB, FILEGROWTH = 1MB)
 COLLATE Latin1_General_100_CI_AS;
GO
ALTER DATABASE shop SET RECOVERY SIMPLE;
GO
USE shop;
CREATE TABLE dbo.fruit (id INT NOT NULL PRIMARY KEY, name NVARCHAR(32) NOT NULL, price DECIMAL(6,2) NULL, stock SMALLINT NOT NULL, note VARCHAR(100) NULL);
INSERT INTO dbo.fruit VALUES (1,N'apple',0.50,120,NULL),(2,N'banana',0.25,300,'ripe'),(3,N'cherry',4.00,15,NULL),(4,N'damson',2.10,0,'out of season'),(5,N'elderberry',NULL,42,NULL);
CREATE TABLE dbo.crate (id INT NOT NULL, label CHAR(8) NOT NULL, weight FLOAT NULL) ON extra;
CREATE CLUSTERED INDEX cx_crate ON dbo.crate (id) ON extra;
INSERT INTO dbo.crate VALUES (1,'small',1.5),(2,'medium',NULL),(3,'large',12.25);
CHECKPOINT;
DBCC SHRINKFILE (shop_log, 0) WITH NO_INFOMSGS;
GO
USE master;
EXEC sp_detach_db 'shop';
GO
