//! MySQL and MariaDB storage files: InnoDB tablespaces (`innodb`: `.ibd`,
//! the `ibdata1` system tablespace, undo and temporary tablespaces, with
//! the MySQL 8 data dictionary stored in them), InnoDB redo logs (`redo`:
//! `ib_logfile*`, MySQL 8.0.30's `#innodb_redo/#ib_redo*` and MariaDB
//! 10.8's unframed log in `redo108`), MyISAM data files (`myd`) and
//! binary logs (`binlog`). Table definitions (`.frm`) and MyISAM indexes (`.MYI`) are in `data::dumps`.

pub mod binlog;
pub mod innodb;
pub mod myd;
pub mod mypack;
pub mod redo;
mod redo108;
