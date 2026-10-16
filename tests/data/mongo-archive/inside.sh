#!/bin/sh
# Runs in a mongo:7 container (see make.sh).
set -eu
mkdir -p /tmp/db
mongod --dbpath /tmp/db --bind_ip 127.0.0.1 --fork --logpath /tmp/mongod.log >/dev/null
{
  mongod --version | head -1
  mongodump --version | head -1
} > /out/version.txt
mongosh --quiet mongodb://127.0.0.1/shop --eval '
db.items.insertMany([
  {_id: ObjectId("650000000000000000000001"), name: "teapot", price: 12.5,
   tags: ["kitchen", "ceramic"], stock: NumberInt(7), sold: NumberLong("123456789012"),
   added: ISODate("2026-01-02T03:04:05.678Z"), active: true, note: null,
   dims: {w: 20, h: 15.5}, code: BinData(0, "AAECAwQ="),
   ref: UUID("0123456789abcdef0123456789abcdef"), cost: NumberDecimal("9.99"),
   pattern: /^tea/i},
  {_id: ObjectId("650000000000000000000002"), name: "mug", price: 4,
   tags: [], stock: NumberInt(30), added: ISODate("2026-01-03T00:00:00Z"), active: false},
  {_id: ObjectId("650000000000000000000003"), name: "spoon", price: 1.25,
   stock: NumberInt(100), ts: Timestamp({t: 1767225600, i: 1}),
   lo: MinKey(), hi: MaxKey()}
]);
db.items.createIndex({name: 1}, {name: "by_name", unique: true});
db.orders.insertMany([
  {_id: 1, item: "teapot", qty: 2},
  {_id: 2, item: "mug", qty: 4}
]);
db.createView("cheap", "items", [{$match: {price: {$lt: 5}}}]);
db.getSiblingDB("notes").memos.insertOne({_id: "first", text: "hello from fillyfoal"});
'
mongodump --quiet --host 127.0.0.1 --numParallelCollections=1 --archive=/out/dump.archive
mongodump --quiet --host 127.0.0.1 --numParallelCollections=1 --gzip --archive=/out/dump.archive.gz
mongod --dbpath /tmp/db --shutdown >/dev/null
