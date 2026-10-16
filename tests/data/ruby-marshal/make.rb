# Writes the ruby-marshal fixtures with Marshal.dump (see make.sh).
dir = ARGV.fetch(0)

Point = Struct.new(:x, :y)

class Item
  def initialize(name, price)
    @name = name
    @price = price
    @tags = [:kitchen, :ceramic]
  end
end

# _dump / _load: user-defined serialisation ('u')
class Colour
  def initialize(rgb)
    @rgb = rgb
  end

  def _dump(_level)
    format('%06x', @rgb)
  end

  def self._load(s)
    new(s.to_i(16))
  end
end

# marshal_dump / marshal_load ('U')
class Money
  def initialize(cents, currency)
    @cents = cents
    @currency = currency
  end

  def marshal_dump
    [@cents, @currency]
  end

  def marshal_load(a)
    @cents, @currency = a
  end
end

module Tagged; end

# A string subclass with an extended module ('e', 'C')
class Label < String; end

shared = 'shared string'
defaulted = Hash.new(0)
defaulted[:hits] = 3
labelled = Label.new('label')
labelled.extend(Tagged)

data = {
  nil: nil, true: true, false: false,
  small: 42, negative: -123, byte: 200, word: 70_000,
  bignum: 2**80, negative_bignum: -(2**70),
  float: 3.25, nan: Float::NAN, infinity: -Float::INFINITY,
  symbol: :fillyfoal, symlink: :fillyfoal,
  utf8: 'čaj', binary: "\x00\x01\xff".b, ascii: 'plain'.encode('US-ASCII'),
  latin1: "caf\xE9".dup.force_encoding('ISO-8859-1'),
  array: [1, 'two', :three, [4.5]],
  same_object: [shared, shared],
  hash: { 'a' => 1, 'b' => [2] },
  default_hash: defaulted,
  struct: Point.new(1, 2),
  object: Item.new('teapot', 12.5),
  user_dump: Colour.new(0x336699),
  user_marshal: Money.new(1999, 'EUR'),
  regexp: /fill+y/i,
  class: String, module: Kernel,
  range: (1..10),
  label: labelled
}
File.binwrite(File.join(dir, 'objects.marshal'), Marshal.dump(data))
# A long array: paging, and a top-level value that is not a hash.
File.binwrite(File.join(dir, 'array.marshal'), Marshal.dump((1..600).map { |i| [i, "item #{i}"] }))
puts RUBY_VERSION
