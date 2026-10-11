#!/bin/bash
# Run inside mongo:7 by mongod.sh.
set -eu
out=$1
db=/tmp/db
rm -rf "$db"
mkdir -p "$db"
mongod --dbpath "$db" --bind_ip 127.0.0.1 --port 27017 --fork --logpath /tmp/mongod.log >/dev/null
mongosh --quiet --eval '
const d = db.getSiblingDB("fillyfoal");
const docs = [];
for (let i = 0; i < 300; i++) {
  docs.push({ _id: i, n: 300 - i, name: "item " + i, tags: ["a", "b"].slice(0, i % 3),
              blob: i % 50 == 0 ? "fillyfoal ".repeat(600) : "short" });
}
d.items.insertMany(docs);
d.items.createIndex({ n: 1 });
const s = d.items.stats({ indexDetails: true });
print("collection " + s.wiredTiger.uri.replace("statistics:table:", ""));
for (const [name, ix] of Object.entries(s.indexDetails)) {
  print("index " + name + " " + ix.uri.replace("statistics:table:", ""));
}
' > /tmp/idents.txt
mongosh --quiet --eval 'db.getSiblingDB("admin").shutdownServer()' >/dev/null 2>&1 || true
while pgrep mongod >/dev/null; do sleep 1; done
# Prefixed so they do not clash with the synthetic fixtures' names.
cp "$db/WiredTiger" "$out/mongod7-WiredTiger"
cp "$db/WiredTiger.turtle" "$out/mongod7-WiredTiger.turtle"
cp "$db/WiredTiger.wt" "$out/mongod7-WiredTiger.wt"
coll=$(awk '$1 == "collection" { print $2 }' /tmp/idents.txt)
cp "$db/$coll.wt" "$out/collection-items.wt"
id=$(awk '$1 == "index" && $2 == "_id_" { print $3 }' /tmp/idents.txt)
cp "$db/$id.wt" "$out/index-items-id.wt"
n=$(awk '$1 == "index" && $2 == "n_1" { print $3 }' /tmp/idents.txt)
cp "$db/$n.wt" "$out/index-items-n.wt"
cp /tmp/idents.txt "$out/idents.txt"
