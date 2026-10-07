# Schema for the Cap'n Proto fixtures (the dissector does not see it).
@0xbf5147cbbecf40c1;

struct Person {
  id @0 :UInt32;
  name @1 :Text;
  email @2 :Text;
  phones @3 :List(PhoneNumber);

  struct PhoneNumber {
    number @0 :Text;
    type @1 :Type;

    enum Type {
      mobile @0;
      home @1;
      work @2;
    }
  }

  employment :union {
    unemployed @4 :Void;
    employer @5 :Text;
    school @6 :Text;
    selfEmployed @7 :Void;
  }

  score @8 :Float64;
  flags @9 :List(Bool);
  photo @10 :Data;
  ratios @11 :List(Float32);
  friends @12 :List(Text);
  balance @13 :Int64;
  matrix @14 :List(List(Int16));
}

struct AddressBook {
  people @0 :List(Person);
}

struct Series {
  values @0 :List(Int32);
}
