// An independent reader of code signatures for the sign-check tests: the
// Security framework's own view (SecStaticCode), where sign_check.py reads
// `codesign --display` text. For each path given it prints, as one JSON
// object: the signing identifier, the code directory flags, whether the
// hardened runtime bit is set, the entitlement keys, and whether the code
// passes a strict static validity check with nested code. Compiled with
// swiftc at test time; it reads signatures and changes nothing.
//
// Usage: codesign_facts path...

import Foundation
import Security

struct Facts: Encodable {
    var identifier: String?
    var flags: UInt32?
    var runtime: Bool
    var entitlements: [String]?
    var valid: Bool
    var error: String?
}

let runtimeFlag: UInt32 = 0x10000

func facts(_ path: String) -> Facts {
    var result = Facts(identifier: nil, flags: nil, runtime: false, entitlements: nil, valid: false, error: nil)
    var code: SecStaticCode?
    let url = URL(fileURLWithPath: path) as CFURL
    let created = SecStaticCodeCreateWithPath(url, [], &code)
    guard created == errSecSuccess, let code else {
        result.error = "SecStaticCodeCreateWithPath \(created)"
        return result
    }
    var info: CFDictionary?
    let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
    let copied = SecCodeCopySigningInformation(code, flags, &info)
    guard copied == errSecSuccess, let dict = info as? [String: Any] else {
        result.error = "SecCodeCopySigningInformation \(copied)"
        return result
    }
    result.identifier = dict[kSecCodeInfoIdentifier as String] as? String
    if let number = dict[kSecCodeInfoFlags as String] as? NSNumber {
        result.flags = number.uint32Value
        result.runtime = number.uint32Value & runtimeFlag != 0
    }
    if let entitlements = dict[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
        result.entitlements = entitlements.keys.sorted()
    } else {
        result.entitlements = []
    }
    let check = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode | kSecCSCheckAllArchitectures)
    let validity = SecStaticCodeCheckValidity(code, check, nil)
    result.valid = validity == errSecSuccess
    if !result.valid {
        result.error = "SecStaticCodeCheckValidity \(validity)"
    }
    return result
}

var all: [String: Facts] = [:]
for path in CommandLine.arguments.dropFirst() {
    all[path] = facts(path)
}
let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
let data = try encoder.encode(all)
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))
