// Owner-authorized one-shot V3 S03 credential handoff on the physical Mac.
// Inputs arrive only as masked ephemeral GitHub environment secrets.
// Never print secret values, overwrite existing identities or touch V2.
import Foundation
import Darwin
import Security

enum ProvisionError: Error {
  case denied(String)
}
func check(_ ok: @autoclosure () -> Bool, _ reason: String) throws {
  guard ok() else { throw ProvisionError.denied(reason) }
}
func existingRegularPrivate(_ url: URL, directory: Bool) throws {
  var st = stat()
  try check(lstat(url.path, &st) == 0, "expected owner-managed V3 path absent")
  if directory {
    try check(st.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) &&
      (st.st_mode & 0o777) == 0o700, "V3 private directory mode invalid")
  } else {
    try check(st.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) &&
      (st.st_mode & 0o777) == 0o600, "V3 private file mode invalid")
  }
}
func notPresent(_ url: URL) throws {
  var st = stat()
  try check(lstat(url.path, &st) != 0 && errno == ENOENT,
    "V3 secret destination already exists or cannot be inspected")
}
func existingItem(_ name: String, from keychain: SecKeychain) throws -> Bool {
  let acct = "amirsheikhzadeh"
  let code = name.withCString { service in
    acct.withCString { account in
      SecKeychainFindGenericPassword(keychain, UInt32(name.utf8.count), service,
        UInt32(acct.utf8.count), account, nil, nil, nil)
    }
  }
  if code == errSecItemNotFound { return false }
  try check(code == errSecSuccess, "V3 existing credential query denied")
  return true
}
func insertItem(_ name: String, bytes: Data, keychain: SecKeychain) throws -> SecKeychainItem {
  let acct = "amirsheikhzadeh"
  var item: SecKeychainItem?
  let status = name.withCString { service in
    acct.withCString { account in
      bytes.withUnsafeBytes { buffer in
        SecKeychainAddGenericPassword(keychain, UInt32(name.utf8.count), service,
          UInt32(acct.utf8.count), account, UInt32(buffer.count),
          buffer.baseAddress, &item)
      }
    }
  }
  try check(status == errSecSuccess && item != nil, "V3 credential import failed")
  return item!
}
func privateWriteNew(_ value: Data, destination: URL) throws {
  let fd = open(destination.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
  try check(fd >= 0, "V3 tunnel token destination not privately writable")
  var success = false
  defer {
    close(fd)
    if !success { _ = unlink(destination.path) }
  }
  try value.withUnsafeBytes { data in
    guard let ptr = data.baseAddress else { throw ProvisionError.denied("empty tunnel credential") }
    var offset = 0
    while offset < data.count {
      let written = write(fd, ptr.advanced(by: offset), data.count - offset)
      try check(written > 0, "V3 private tunnel token write failed")
      offset += written
    }
  }
  try check(fsync(fd) == 0, "V3 tunnel file fsync failed")
  try existingRegularPrivate(destination, directory: false)
  success = true
}
do {
  try check(CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--stage",
    "explicit owner S03 provisioning invocation required")
  try check(ProcessInfo.processInfo.environment["RUNNER_NAME"] == "radlina-macbook-main",
    "pinned Mac GitHub runner required")
  try check(NSUserName() == "amirsheikhzadeh", "physical Mac owner required")
  try check(Host.current().localizedName == "amirs-MacBook-Pro.local" ||
    ProcessInfo.processInfo.hostName == "amirs-MacBook-Pro.local",
    "pinned physical Mac hostname required")
  _ = umask(0o077)
  let env = ProcessInfo.processInfo.environment
  let names = [
    "RADLINA_V3_S03_WRITER_TOKEN_STAGE",
    "RADLINA_V3_S03_WRITER_HMAC_STAGE",
    "RADLINA_V3_S03_MAC_TUNNEL_STAGE"
  ]
  try check(names.allSatisfy { env[$0] != nil && !(env[$0] ?? "").isEmpty },
    "missing approved ephemeral GitHub environment secrets")
  var writer = Data((env[names[0]] ?? "").trimmingCharacters(in:.whitespacesAndNewlines).utf8)
  var hmacText = Data((env[names[1]] ?? "").trimmingCharacters(in:.whitespacesAndNewlines).utf8)
  var tunnel = Data((env[names[2]] ?? "").trimmingCharacters(in:.whitespacesAndNewlines).utf8)
  defer {
    writer.resetBytes(in: 0..<writer.count)
    hmacText.resetBytes(in: 0..<hmacText.count)
    tunnel.resetBytes(in: 0..<tunnel.count)
  }
  try check(writer.count >= 32 && writer.count <= 512 &&
    writer.allSatisfy { $0 > 32 && $0 < 127 }, "V3 bearer token bounds invalid")
  let ascii = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
  let hmacString = String(decoding: hmacText, as: UTF8.self)
  try check(hmacString.unicodeScalars.allSatisfy { ascii.contains($0) } &&
    Data(base64Encoded: hmacString) != nil, "V3 HMAC encoding invalid")
  var decodedHmac = Data(base64Encoded: hmacString)!
  defer { decodedHmac.resetBytes(in: 0..<decodedHmac.count) }
  try check(decodedHmac.count >= 32 && decodedHmac.count <= 128, "V3 HMAC key entropy size invalid")
  try check(tunnel.count >= 100 && tunnel.count <= 8192 &&
    tunnel.allSatisfy { $0 > 32 && $0 < 127 }, "V3 Cloudflare tunnel token bounds invalid")
  let base = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".local/share/radlina/v3-beta")
  let runner = base.appendingPathComponent("macbook-main-runner")
  let s03 = base.appendingPathComponent("macbook-main-s03")
  try existingRegularPrivate(runner, directory: true)
  try existingRegularPrivate(s03, directory: true)
  let db = runner.appendingPathComponent("v3-device.keychain-db")
  let passFile = runner.appendingPathComponent("keychain-password.local")
  let tunnelFile = s03.appendingPathComponent("cloudflare-tunnel-token.secret")
  let stagedWriter = s03.appendingPathComponent("s03-writer-token.secret")
  let stagedHmac = s03.appendingPathComponent("s03-writer-hmac.b64")
  try existingRegularPrivate(db, directory: false)
  try existingRegularPrivate(passFile, directory: false)
  for file in [tunnelFile, stagedWriter, stagedHmac] { try notPresent(file) }
  var keychainRef: SecKeychain?
  let opened = SecKeychainOpen(db.path, &keychainRef)
  guard opened == errSecSuccess, let keychain = keychainRef else {
    throw ProvisionError.denied("existing owner-dedicated Mac Keychain unavailable")
  }
  var password = try Data(contentsOf: passFile)
  if password.last == 10 { password.removeLast() }
  try check(password.count >= 40 && password.count <= 200, "dedicated Keychain metadata invalid")
  let unlocked = password.withUnsafeBytes {
    SecKeychainUnlock(keychain, UInt32(password.count), $0.baseAddress, true)
  }
  password.resetBytes(in: 0..<password.count)
  try check(unlocked == errSecSuccess, "dedicated Keychain owner-unlock denied")
  let tokenName = "com.radlina.remote-mcp.v3.s03-writer-token"
  let hmacName = "com.radlina.remote-mcp.v3.s03-writer-hmac-base64"
  try check(try !existingItem(tokenName, from: keychain) &&
    !existingItem(hmacName, from: keychain),
    "existing S03 writer items must be reconciled, not overwritten")
  var created = [SecKeychainItem]()
  do {
    created.append(try insertItem(tokenName, bytes: writer, keychain: keychain))
    created.append(try insertItem(hmacName, bytes: hmacText, keychain: keychain))
    try privateWriteNew(tunnel, destination: tunnelFile)
  } catch {
    for item in created.reversed() { _ = SecKeychainItemDelete(item) }
    throw error
  }
  print("V3_S03_MAC_EXISTING_OWNER_CREDENTIALS_SECURELY_STAGED=true")
  print("V3_S03_MAC_DEDICATED_KEYCHAIN_BOTH_ITEMS_PRESENT=true")
  print("V3_S03_MAC_TUNNEL_PRIVATE_FILE_MODE_0600=true")
  print("V3_S03_NO_SECRET_VALUES_PRINTED_OR_COMMITTED=true")
  print("V3_S03_I01_NOT_YET_ACCEPTED=true")
} catch {
  fputs("V3_S03_MAC_PROVISIONING_DENIED_PRECONDITION_OR_SECURE_STAGING_FAILURE\n", stderr)
  exit(16)
}
