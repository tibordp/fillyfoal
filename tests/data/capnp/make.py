"""Writes the external Cap'n Proto fixtures with pycapnp (the C++
reference implementation underneath), from `book.capnp`.

    uv run --with pycapnp==2.2.4 python make.py
"""

import os

import capnp

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "external")
book = capnp.load(os.path.join(HERE, "book.capnp"))


def fill(msg):
    people = msg.init("people", 2)
    alice = people[0]
    alice.id = 123
    alice.name = "Alice"
    alice.email = "alice@example.com"
    phones = alice.init("phones", 1)
    phones[0].number = "555-1212"
    phones[0].type = "mobile"
    alice.employment.school = "MIT"
    alice.score = 0.75
    alice.flags = [True, False, True, True]
    alice.photo = b"\x89PNG\x00\x01\x02"
    alice.ratios = [0.5, -1.25]
    alice.friends = ["Bob", "Carol"]
    alice.balance = -42
    alice.matrix = [[1, 2], [-3]]
    bob = people[1]
    bob.id = 456
    bob.name = "Bob"
    bob.employment.unemployed = None
    return msg


def write(path, data):
    with open(os.path.join(OUT, path), "wb") as f:
        f.write(data)


write("capnp/book.bin", fill(book.AddressBook.new_message()).to_bytes())
# A small first segment: the rest spills into more segments, reached
# through far pointers.
write(
    "capnp/book-segments.bin",
    fill(book.AddressBook.new_message(num_first_segment_words=8)).to_bytes(),
)
series = book.Series.new_message()
series.values = [(i * 37) % 1000 - 500 for i in range(1200)]
write("capnp/series.bin", series.to_bytes())
write("capnp-packed/book.packed", fill(book.AddressBook.new_message()).to_bytes_packed())
