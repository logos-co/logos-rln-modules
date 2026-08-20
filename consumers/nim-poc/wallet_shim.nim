## In-process replacement for the `lez_core` wallet module: Nim bindings to
## the lez `wallet-ffi` C ABI (logos-execution-zone @ the repo's flake pin,
## cbindgen header `lez/wallet-ffi/wallet_ffi.h`) plus the three wire
## methods `liblogos_lez_rln_module` actually calls (deps/lez_core.lidl):
## account_id_from_base58, get_account_public,
## send_generic_public_transaction.
##
## Wire conventions (mirrors the lez_core C++ module, and matches what the
## lez-rln module parses — its lib.rs is the authoritative consumer):
## - every reply is a bare string value; "" means failure;
## - get_account_public: serialized {"program_owner","balance","nonce","data"}
##   — program_owner 64-hex (FfiProgramId's 32 raw bytes), balance/nonce
##   16-byte-LE hex, data hex or "";
## - send_generic_public_transaction args are the frozen 4-element array
##   [[id_hex...],[bool...],[u32 words...],program_id_hex].
##
## The wallet handle is guarded by one global lock: the C++ module needed no
## locking only because logos-core serialized its dispatch; here calls come
## from the main thread and lp pool workers.

import std/[json, locks, os, strutils]

# ------------------------------------------------------------ C ABI
# Struct layouts transcribed from the pinned wallet_ffi.h; every struct is
# passed exactly as the header declares (note the by-value FfiBytes32 /
# FfiProgramId parameters).

type
  WalletHandle = object
  FfiBytes32* {.bycopy.} = object
    data*: array[32, uint8]
  FfiProgramId* {.bycopy.} = object
    data*: array[8, uint32]
  FfiU128* {.bycopy.} = object
    data*: array[16, uint8]
  FfiAccount* {.bycopy.} = object
    programOwner*: FfiProgramId
    balance*: FfiU128
    data*: ptr uint8
    dataLen*: csize_t
    nonce*: FfiU128
  FfiAccountIdentity* {.bycopy.} = object
    kind*: cint
    accountId*: FfiBytes32
    keyPath*: cstring
    nullifierSecretKey*: FfiBytes32
    nullifierPublicKey*: FfiBytes32
    viewingPublicKey*: ptr uint8
    viewingPublicKeyLen*: csize_t
    identifier*: FfiU128
  FfiTransactionResult* {.bycopy.} = object
    txHash*: cstring
    success*: bool
    secretsData*: ptr FfiBytes32
    secretsSize*: csize_t
  FfiCreateWalletOutput* {.bycopy.} = object
    wallet*: ptr WalletHandle
    mnemonic*: cstring

const WalletFfiSuccess = 0

{.push cdecl.}
proc wallet_ffi_create_new(configPath, storagePath, statisticsPath,
    password: cstring): FfiCreateWalletOutput {.importc.}
proc wallet_ffi_open(configPath, storagePath, statisticsPath: cstring):
    ptr WalletHandle {.importc.}
proc wallet_ffi_destroy(handle: ptr WalletHandle) {.importc.}
proc wallet_ffi_save(handle: ptr WalletHandle): cint {.importc.}
proc wallet_ffi_sync_to_block(handle: ptr WalletHandle, blockId: uint64): cint {.importc.}
proc wallet_ffi_get_last_synced_block(handle: ptr WalletHandle,
    outBlockId: ptr uint64): cint {.importc.}
proc wallet_ffi_get_current_block_height(handle: ptr WalletHandle,
    outBlockHeight: ptr uint64): cint {.importc.}
proc wallet_ffi_get_account_public(handle: ptr WalletHandle, accountId: ptr FfiBytes32,
    outAccount: ptr FfiAccount): cint {.importc.}
proc wallet_ffi_free_account_data(account: ptr FfiAccount) {.importc.}
proc wallet_ffi_account_id_from_base58(base58Str: cstring,
    outAccountId: ptr FfiBytes32): cint {.importc.}
proc wallet_ffi_resolve_public_account(accountId: FfiBytes32, needsSign: bool,
    outAccountIdentity: ptr FfiAccountIdentity): cint {.importc.}
proc wallet_ffi_free_account_identity(accountIdentity: ptr FfiAccountIdentity) {.importc.}
proc wallet_ffi_send_generic_public_transaction(handle: ptr WalletHandle,
    accountIdentities: ptr FfiAccountIdentity, accountIdentitiesSize: csize_t,
    instructionWords: ptr uint32, instructionWordsSize: csize_t,
    programId: FfiProgramId, outResult: ptr FfiTransactionResult): cint {.importc.}
proc wallet_ffi_free_transaction_result(res: ptr FfiTransactionResult) {.importc.}
proc wallet_ffi_free_string(p: cstring) {.importc.}
{.pop.}

# ------------------------------------------------------------ state

var
  walletLock: Lock
  wallet: ptr WalletHandle

initLock walletLock

type WalletError* = object of CatchableError

template withWallet(body: untyped) =
  acquire walletLock
  try:
    body
  finally:
    release walletLock

# ------------------------------------------------------------ helpers

proc toHex(p: pointer, n: int): string =
  const digits = "0123456789abcdef"
  result = newString(n * 2)
  let bytes = cast[ptr UncheckedArray[uint8]](p)
  for i in 0 ..< n:
    result[i * 2] = digits[int(bytes[i] shr 4)]
    result[i * 2 + 1] = digits[int(bytes[i] and 0x0f)]

proc hexToBytes32(hex: string): FfiBytes32 =
  var digits = hex.strip()
  if digits.startsWith("0x") or digits.startsWith("0X"):
    digits = digits[2 .. ^1]
  if digits.len != 64:
    raise newException(WalletError, "expected 64 hex chars, got " & $digits.len)
  for i in 0 ..< 32:
    result.data[i] = uint8(parseHexInt(digits[i * 2 .. i * 2 + 1]))

# ------------------------------------------------------------ lifecycle

proc walletOpenOrCreate*(configPath, storagePath, statisticsPath,
    password: string): tuple[created: bool, mnemonic: string] =
  ## Open when storage.json exists, create otherwise (mirroring the
  ## membership UI's onboarding decision). create_new does not persist —
  ## save immediately so a crash cannot orphan the mnemonic's accounts.
  withWallet:
    if wallet != nil:
      return (false, "")
    if fileExists(storagePath):
      wallet = wallet_ffi_open(configPath.cstring, storagePath.cstring,
        statisticsPath.cstring)
      if wallet.isNil:
        raise newException(WalletError, "wallet_ffi_open failed for " & storagePath)
      return (false, "")
    var created = wallet_ffi_create_new(configPath.cstring, storagePath.cstring,
      statisticsPath.cstring, password.cstring)
    if created.wallet.isNil:
      raise newException(WalletError, "wallet_ffi_create_new failed for " & storagePath)
    wallet = created.wallet
    result = (true, $created.mnemonic)
    wallet_ffi_free_string(created.mnemonic)
    if wallet_ffi_save(wallet) != WalletFfiSuccess:
      raise newException(WalletError, "wallet_ffi_save failed after create_new")

proc walletClose*() =
  withWallet:
    if wallet != nil:
      discard wallet_ffi_save(wallet)
      wallet_ffi_destroy(wallet)
      wallet = nil

proc walletSyncStatus*(): tuple[synced, head: uint64] =
  withWallet:
    if wallet.isNil: raise newException(WalletError, "wallet not open")
    if wallet_ffi_get_last_synced_block(wallet, addr result.synced) != WalletFfiSuccess:
      raise newException(WalletError, "get_last_synced_block failed")
    if wallet_ffi_get_current_block_height(wallet, addr result.head) != WalletFfiSuccess:
      raise newException(WalletError, "get_current_block_height failed (sequencer unreachable?)")

proc walletSyncToHead*(chunk: uint64 = 500) =
  ## Strictly serial chunked sync to the sequencer head (the wallet serves
  ## no reads while a sync is in flight, and a tx from an unsynced wallet is
  ## accepted but never applies). Re-probes the head after catching up in
  ## case it advanced during the sync.
  var pass = 0
  while true:
    var (synced, head) = walletSyncStatus()
    if synced >= head:
      echo "wallet synced at block ", synced
      break
    inc pass
    if pass > 100:
      raise newException(WalletError, "sync not converging after 100 passes")
    echo "wallet sync: ", synced, " -> ", head
    while synced < head:
      let target = min(synced + chunk, head)
      withWallet:
        if wallet_ffi_sync_to_block(wallet, target) != WalletFfiSuccess:
          raise newException(WalletError, "sync_to_block " & $target & " failed")
      synced = target
  withWallet:
    discard wallet_ffi_save(wallet)

# ------------------------------------------------------------ wire methods

proc wireAccountIdFromBase58(args: JsonNode): string =
  var outId: FfiBytes32
  if wallet_ffi_account_id_from_base58(args[0].getStr.cstring, addr outId) != WalletFfiSuccess:
    return ""
  toHex(addr outId.data[0], 32)

proc wireGetAccountPublic(args: JsonNode): string =
  var id: FfiBytes32
  try:
    id = hexToBytes32(args[0].getStr)
  except WalletError:
    return ""
  var acct: FfiAccount
  if wallet_ffi_get_account_public(wallet, addr id, addr acct) != WalletFfiSuccess:
    return ""
  let reply = %*{
    "program_owner": toHex(addr acct.programOwner.data[0], 32),
    "balance": toHex(addr acct.balance.data[0], 16),
    "nonce": toHex(addr acct.nonce.data[0], 16),
    "data": (if acct.data.isNil or acct.dataLen == 0: ""
             else: toHex(acct.data, int(acct.dataLen))),
  }
  wallet_ffi_free_account_data(addr acct)
  $reply

proc wireSendGenericPublicTx(args: JsonNode): string =
  # [[id_hex...], [needs_sign...], [u32 words...], program_id_hex]
  let ids = args[0]
  let signs = args[1]
  let wordsJson = args[2]
  if ids.len != signs.len or ids.len == 0:
    return ""
  var identities = newSeq[FfiAccountIdentity](ids.len)
  var resolved = 0
  defer:
    for i in 0 ..< resolved:
      wallet_ffi_free_account_identity(addr identities[i])
  for i in 0 ..< ids.len:
    var id: FfiBytes32
    try:
      id = hexToBytes32(ids[i].getStr)
    except WalletError:
      return ""
    if wallet_ffi_resolve_public_account(id, signs[i].getBool,
        addr identities[i]) != WalletFfiSuccess:
      return ""
    inc resolved
  var words = newSeq[uint32](wordsJson.len)
  for i in 0 ..< wordsJson.len:
    words[i] = uint32(wordsJson[i].getBiggestInt)
  var programId: FfiProgramId
  try:
    let raw = hexToBytes32(args[3].getStr)
    copyMem(addr programId.data[0], unsafeAddr raw.data[0], 32)
  except WalletError:
    return ""
  var txr: FfiTransactionResult
  if wallet_ffi_send_generic_public_transaction(wallet, addr identities[0],
      csize_t(identities.len),
      (if words.len > 0: addr words[0] else: nil), csize_t(words.len),
      programId, addr txr) != WalletFfiSuccess:
    return ""
  var secrets = newJArray()
  if not txr.secretsData.isNil:
    let arr = cast[ptr UncheckedArray[FfiBytes32]](txr.secretsData)
    for i in 0 ..< int(txr.secretsSize):
      secrets.add %toHex(addr arr[i].data[0], 32)
  let reply = %*{
    "success": txr.success,
    "tx_hash": (if txr.txHash.isNil: "" else: $txr.txHash),
    "secrets": secrets,
    "error": "",
  }
  wallet_ffi_free_transaction_result(addr txr)
  $reply

proc walletDispatch*(meth, argsJson: string): string {.nimcall, gcsafe.} =
  ## The lp shim's handler for target "lez_core". "" = failure (the caller's
  ## convention); never raises across the shim boundary.
  {.cast(gcsafe).}:
    try:
      let args = parseJson(argsJson)
      withWallet:
        if wallet.isNil:
          stderr.writeLine "wallet_shim: " & meth & " before wallet open"
          return ""
        case meth
        of "account_id_from_base58": result = wireAccountIdFromBase58(args)
        of "get_account_public": result = wireGetAccountPublic(args)
        of "send_generic_public_transaction": result = wireSendGenericPublicTx(args)
        else:
          stderr.writeLine "wallet_shim: unsupported method " & meth
          result = ""
    except CatchableError as e:
      stderr.writeLine "wallet_shim: " & meth & " raised: " & e.msg
      result = ""
