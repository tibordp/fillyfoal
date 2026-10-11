// Writes an alias file (the header `URL.writeBookmarkData` adds around
// bookmark data) for TARGET at OUT. Usage: swift make_alias.swift TARGET OUT
import Foundation

let args = CommandLine.arguments
let target = URL(fileURLWithPath: args[1])
let data = try target.bookmarkData(
    options: .suitableForBookmarkFile, includingResourceValuesForKeys: nil, relativeTo: nil)
try URL.writeBookmarkData(data, to: URL(fileURLWithPath: args[2]))
