// Radlina V3 I01 — import two already provisioned writer items from the
// existing dedicated Mac Keychain. This program NEVER creates credentials,
// exports them through stdout/argv, or accesses the default login Keychain.
// Executed only by the explicit, owner-scoped --stage importer on physical Mac.
import Darwin
import Foundation
import Security

enum StageFailure: Error {
  case denied(String)
}
func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
  if !condition() { throw StageFailure.denied(reason) }
}
func privateMode(_ url: URL, directory: Bool) throws {
  let fm = FileManager.default
  let item = try fm.attributesOfItem(atPath: url.path)
  guard let mode = item[.posixPermissions] as? NSNumber,
    (mode.intValue & 0o077) == 0,
    (mode.intValue & 0o700) == (directory ? 0o700 : 0o600) else {
    throw StageFailure.denied("owner-dedicated V3 private file permissions invalid")
  }
  var info = stat()
  if lstat(url.path, &info) != 0 ||
    (directory ? ((info.st_mode & mode_t(S_IFMT)) != mode_t(S_IFDIR))
               : ((info.st_mode & mode_t(S_IFMT)) != mode_t(S_IFREG))) {
    throw StageFailure.denied("V3 private path is missing or not a regular non-link")
  }
}
func existing(_ path: URL) -> Bool {
  var info = stat()
  return lstat(path.path, &info) == 0
}
func safeWrite(_ contents: Data, to url: URL) throws {
  let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
  guard fd >= 0 else { throw StageFailure.denied("V3 private destination exists or cannot be created") }
  var ok = false
  defer {
    close(fd)
    if !ok { _ = unlink(url.path) }
  }
  try contents.withUnsafeBytes { pointer in
    guard let base = pointer.baseAddress else { throw StageFailure.denied("empty writer credential") }
    var offset = 0
    while offset < pointer.count {
      let count = write(fd, base.advanced(by: offset), pointer.count - offset)
      guard count > 0 else { throw StageFailure.denied("private writer file write failed") }
      offset += count
    }
  }
  guard fsync(fd) == 0 else { throw StageFailure.denied("private writer file fsync failed") }
  try privateMode(url, directory: false)
  ok = true
}
func secret(_ service: String, from keychain: SecKeychain) throws -> Data {
  let account = "amirsheikhzadeh"
  var size: UInt32 = 0
  var pointer: UnsafeMutableRawPointer?
  let status = service.withCString { servicePtr in
    account.withCString { accountPtr in
      SecKeychainFindGenericPassword(
        keychain, UInt32(service.utf8.count), servicePtr,
        UInt32(account.utf8.count), accountPtr, &size, &pointer, nil
      )
    }
  }
  guard status == errSecSuccess, let pointer, size > 0, size <= 4096 else {
    throw StageFailure.denied("required existing V3 writer item absent from owner-dedicated Keychain")
  }
  defer { SecKeychainItemFreeContent(nil, pointer) }
  return Data(bytes: pointer, count: Int(size))
}
do {
  try require(CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--stage",
    "explicit V3 I01 owner-staging mode required")
  try require(ProcessInfo.processInfo.environment["USER"] == "amirsheikhzadeh",
    "physical Mac owner account required")
  var hostnameBuffer = [CChar](repeating: 0, count: 256)
  try require(gethostname(&hostnameBuffer, hostnameBuffer.count) == 0,
    "physical Mac hostname lookup failed")
  try require(String(cString: hostnameBuffer) == "amirs-MacBook-Pro.local",
    "exact physical Mac hostname required")

  _ = umask(0o077)
  let home = FileManager.default.homeDirectoryForCurrentUser
  let root = home.appendingPathComponent(".local/share/radlina/v3-beta")
  let dedicated = root.appendingPathComponent("macbook-main-runner")
  let state = root.appendingPathComponent("macbook-main-s03")
  let database = dedicated.appendingPathComponent("v3-device.keychain-db")
  let passwordFile = dedicated.appendingPathComponent("keychain-password.local")
  let tokenFile = state.appendingPathComponent("s03-writer-token.secret")
  let hmacFile = state.appendingPathComponent("s03-writer-hmac.b64")

  try privateMode(dedicated, directory: true)
  try privateMode(state, directory: true)
  try privateMode(database, directory: false)
  try privateMode(passwordFile, directory: false)
  try require(!existing(tokenFile) && !existing(hmacFile),
    "existing staged writer files require explicit reconciliation; refusing overwrite")

  var ref: SecKeychain?
  let result = SecKeychainOpen(database.path, &ref)
  guard result == errSecSuccess, let ref else {
    throw StageFailure.denied("existing owner-dedicated Mac Keychain unavailable")
  }
  var pass = try Data(contentsOf: passwordFile)
  if pass.last == 10 { pass.removeLast() }
  try require(pass.count >= 40 && pass.count <= 200,
    "dedicated Keychain unlock metadata invalid")
  let unlock = pass.withUnsafeBytes {
    SecKeychainUnlock(ref, UInt32(pass.count), $0.baseAddress, true)
  }
  pass.resetBytes(in: 0..<pass.count)
  try require(unlock == errSecSuccess,
    "owner-dedicated Mac Keychain cannot unlock without local user authorization")

  var token = try secret("com.radlina.remote-mcp.v3.s03-writer-token", from: ref)
  var hmac = try secret("com.radlina.remote-mcp.v3.s03-writer-hmac-base64", from: ref)
  defer {
    token.resetBytes(in: 0..<token.count)
    hmac.resetBytes(in: 0..<hmac.count)
  }
  let tokenText = String(decoding: token, as: UTF8.self)
  let hmacText = String(decoding: hmac, as: UTF8.self)
  try require(tokenText.utf8.count >= 32 && tokenText.utf8.count <= 512 &&
    tokenText.allSatisfy({ !$0.isWhitespace && $0.isASCII }),
    "V3 writer token constraints invalid")
  let charset = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
  try require(hmacText.unicodeScalars.allSatisfy({ charset.contains($0) }),
    "V3 HMAC Base64 encoding invalid")
  guard let decoded = Data(base64Encoded: hmacText),
    decoded.count >= 32 && decoded.count <= 128 else {
    throw StageFailure.denied("V3 HMAC must decode to 256-1024 secret bits")
  }
  // Two-file staging is all-or-nothing on failure. Neither Keychain item is
  // changed, and no service is started here.
  try safeWrite(token, to: tokenFile)
  do {
    try safeWrite(hmac, to: hmacFile)
  } catch {
    _ = unlink(tokenFile.path)
    throw error
  }
  print("V3_MAC_S03_EXISTING_DEDICATED_KEYCHAIN_WRITER_FILES_STAGED")
  print("Writer credentials remain Mac-local; no values printed; no service started")
} catch {
  fputs("V3_MAC_S03_IMPORT_NOT_COMPLETED: owner-provisioned Keychain inputs or valid staging context required\n", stderr)
  exit(16)
}
