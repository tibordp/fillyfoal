// Writes tests/fixtures/external/realm/people.realm with Realm JS (the
// prebuilt Realm Core shipped in the `realm` npm package):
//
//   npm install realm@20.2.0        (in a scratch directory; set
//                                    REALM_DISABLE_ANALYTICS=1)
//   node make_fixture.mjs OUT.realm
//
// Three classes (300 objects in one, so its cluster tree has an inner
// node), a primary key, optional and list properties, a link and
// most scalar types; the file is compacted so it holds one clean version.

import Realm from "realm";
import fs from "node:fs";

const out = process.argv[2];
for (const p of [out, out + ".lock", out + ".note"]) {
  fs.rmSync(p, { force: true });
}
fs.rmSync(out + ".management", { recursive: true, force: true });

const Dog = {
  name: "Dog",
  properties: { name: "string", weight: "double" },
};
const Reading = {
  name: "Reading",
  properties: { n: "int", v: "double", note: "string?" },
};
const Person = {
  name: "Person",
  primaryKey: "_id",
  properties: {
    _id: "int",
    name: "string",
    age: "int?",
    active: "bool",
    score: "float",
    born: "date",
    photo: "data?",
    tags: "string[]",
    dog: "Dog?",
  },
};

const realm = await Realm.open({ path: out, schema: [Person, Dog, Reading], schemaVersion: 3 });
realm.write(() => {
  const rex = realm.create("Dog", { name: "Rex", weight: 12.5 });
  realm.create("Dog", { name: "Fido", weight: 30 });
  realm.create("Person", {
    _id: 1,
    name: "Ada",
    age: 36,
    active: true,
    score: 9.5,
    born: new Date("1815-12-10T00:00:00Z"),
    photo: new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer,
    tags: ["math", "engines"],
    dog: rex,
  });
  realm.create("Person", {
    _id: 2,
    name: "Grace",
    age: null,
    active: false,
    score: 7.25,
    born: new Date("1906-12-09T00:00:00Z"),
    tags: [],
  });
  realm.create("Person", {
    _id: 3,
    name: "Linus",
    age: 21,
    active: true,
    score: 1,
    born: new Date("1969-12-28T00:00:00Z"),
    tags: ["kernel"],
  });
});
realm.write(() => {
  // Enough objects for the cluster tree to grow an inner node.
  for (let n = 0; n < 300; n++) {
    realm.create("Reading", {
      n,
      v: n / 4,
      note: n % 50 === 0 ? `a longer note for reading number ${n}` : null,
    });
  }
});
realm.compact();
realm.close();
for (const p of [out + ".lock", out + ".note"]) {
  fs.rmSync(p, { force: true });
}
fs.rmSync(out + ".management", { recursive: true, force: true });
// Realm keeps the event loop alive after close.
process.exit(0);
