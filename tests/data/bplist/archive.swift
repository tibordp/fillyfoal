// Writes an NSKeyedArchiver archive (a binary plist) with Foundation's own
// archiver: strings, numbers, a date, data, a URL, a UUID, nested arrays,
// dictionaries and sets, and an object referenced twice.
//
//   swift tests/data/bplist/archive.swift OUT.plist
import Foundation

let shared = NSString(string: "shared value")
let root: NSDictionary = [
    "name": "fillyfoal",
    "count": NSNumber(value: 42),
    "ratio": NSNumber(value: 0.75),
    "enabled": NSNumber(value: true),
    "when": NSDate(timeIntervalSinceReferenceDate: 812_896_200),
    "blob": NSData(bytes: [0, 1, 2, 0x68, 0x69] as [UInt8], length: 5),
    "link": NSURL(string: "https://example.com/fillyfoal")!,
    "id": NSUUID(uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF")!,
    "list": NSArray(array: ["one", NSNumber(value: 2), shared]),
    "tags": NSSet(array: ["a", "b"]),
    "nested": NSDictionary(dictionary: ["again": shared, "empty": NSArray()]),
]
let data = try NSKeyedArchiver.archivedData(withRootObject: root, requiringSecureCoding: false)
try data.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
