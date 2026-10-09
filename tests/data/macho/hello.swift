protocol Greeter {
    func greet(_ name: String) -> String
}

struct Polite: Greeter {
    var punctuation: String
    func greet(_ name: String) -> String { "Hello, \(name)\(punctuation)" }
}

final class Counter {
    var count = 0
    func next() -> Int { count += 1; return count }
}

enum Mood { case happy, curious }

let counter = Counter()
let greeter: Greeter = Polite(punctuation: "!")
for name in ["world", "fillyfoal"] {
    print(greeter.greet(name), counter.next(), Mood.curious)
}
