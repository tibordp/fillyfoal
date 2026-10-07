//! Data serialisation and database files: Arrow, Avro, Parquet, ORC, HDF5,
//! NetCDF, MATLAB, NumPy and safetensors, pickles, CBOR, MessagePack, BSON,
//! Amazon Ion, Smile and UBJSON (shared presentation in `valuetree`), bencode, binary
//! plists, Berkeley DB, Access (Jet), ESE, LevelDB/RocksDB tables, embedded
//! databases (`embedded_db`), backups and database dumps (`dumps`), R and
//! ASDF data (`rdata`), Bitcoin block files, and schemaless wire encodings
//! (`wire`: protobuf, FlatBuffers, Thrift, Cap'n Proto).

pub mod arrow;
pub mod avro;
pub mod bdb;
pub mod bencode;
pub mod bitcoin;
pub mod bplist;
pub mod bson;
pub mod cbor;
pub mod dumps;
pub mod embedded_db;
pub mod ese;
pub mod hdf5;
pub mod ion;
pub mod jet;
pub mod matlab;
pub mod msgpack;
pub mod netcdf;
pub mod npy;
pub mod orc;
pub mod parquet;
pub mod pickle;
pub mod rdata;
pub mod smile;
pub mod sst;
pub mod ubjson;
pub mod valuetree;
pub mod wire;
