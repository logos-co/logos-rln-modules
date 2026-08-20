## Standalone RLN membership registration against the real module stack —
## no logos-core. Loads liblogos_rln_module + liblogos_lez_rln_module as
## cdylibs, serves their lp_* wire from lp_shim, and backs the "lez_core"
## wallet target with wallet_shim over libwallet_ffi.
##
## Modes:
##   probe    — provision wallet-home, open+sync the wallet, start() the
##              module, read registry parameters + funding balance. No writes
##              beyond wallet storage. The connectivity dry-run.
##   register — probe + unlock_keystore + register(funded) + poll the
##              membership to "active".
##   full     — register + a proof round-trip: generate_proof, verify_proof
##              (expect "valid"), re-verify the same signal (expect
##              "duplicate" from the nullifier log).
##   claim    — testnet bootstrap convenience: probe + claim_tokens from the
##              registry's faucet into --funding, then poll the balance.
##              (One lez-rln dispatch — the wallet shim gains no surface.)
##
## See README.md for the runbook and failure triage.

import std/[json, locks, os, parseopt, strutils, times]
import module_host, lp_shim, wallet_shim

type Config = object
  registry: string        # CAIP-10 "logos:<ref>:<64-hex config PDA>"
  funding: string         # pre-funded holding account (base58 or 64-hex)
  rlnId: string           # 64-hex application scope key
  rateLimit: int
  password: string
  walletPassword: string
  sequencer: string
  dataDir: string
  rlnLib: string
  lezLib: string
  epochSize: int
  mode: string
  signal: string          # hex payload for the proof round-trip
  claimAmount: int        # 0 = derive from rate limit and registry price

proc usage() =
  quit("""usage: register_poc --registry=<caip10> [options]
  --registry     logos:<ref>:<64-hex config PDA>            (required)
  --funding      funded holding account, base58 or 64-hex   (required for register/full)
  --rln-id       64-hex application scope key               (default: "nim-poc" padded)
  --rate-limit   requested rate limit                       (default 100)
  --password     keystore password                          (default poc-pass)
  --wallet-password  wallet password for create_new         (default: --password)
  --sequencer    sequencer URL          (default https://testnet.lez.logos.co/)
  --data-dir     host-owned persistence root                (default ./poc-data)
  --rln-lib      path to libliblogos_rln_module cdylib
  --lez-lib      path to libliblogos_lez_rln_module cdylib
  --epoch-size   epoch_size_sec for start()                 (default 600)
  --signal       signal hex for the proof round-trip        (default "nim-poc signal")
  --claim-amount tokens for --mode claim    (default rate_limit x price x 2)
  --mode         probe | claim | register | full            (default full)""", 2)

proc parseArgs(): Config =
  result.rateLimit = 100
  result.password = "poc-pass"
  result.sequencer = "https://testnet.lez.logos.co/"
  result.dataDir = "poc-data"
  result.epochSize = 600
  result.mode = "full"
  result.rlnId = toHex(alignLeft("nim-poc", 32, '\0')).toLowerAscii
  result.signal = toHex("nim-poc signal").toLowerAscii
  for kind, key, val in getopt():
    if kind notin {cmdLongOption, cmdShortOption}: usage()
    case key
    of "registry": result.registry = val
    of "funding": result.funding = val
    of "rln-id": result.rlnId = val
    of "rate-limit": result.rateLimit = parseInt(val)
    of "password": result.password = val
    of "wallet-password": result.walletPassword = val
    of "sequencer": result.sequencer = val
    of "data-dir": result.dataDir = val
    of "rln-lib": result.rlnLib = val
    of "lez-lib": result.lezLib = val
    of "epoch-size": result.epochSize = parseInt(val)
    of "signal": result.signal = val
    of "claim-amount": result.claimAmount = parseInt(val)
    of "mode": result.mode = val
    else: usage()
  if result.walletPassword.len == 0: result.walletPassword = result.password
  if result.registry.len == 0: usage()
  if result.mode notin ["probe", "claim", "register", "full"]: usage()
  if result.mode != "probe" and result.funding.len == 0:
    quit("--funding is required for mode " & result.mode, 2)
  if result.mode == "claim" and result.claimAmount < 0:
    quit("--claim-amount must be positive", 2)
  let parts = result.registry.split(':')
  if parts.len != 3 or parts[2].len != 64:
    quit("--registry must be logos:<ref>:<64-hex config PDA>", 2)
  # Default lib locations: the cdylib build dirs in this repo's rust-libs.
  let repoRoot = currentSourcePath().parentDir.parentDir.parentDir
  if result.rlnLib.len == 0:
    result.rlnLib = repoRoot / "logos-rln-module/rust-lib/target/release/libliblogos_rln_module.dylib"
  if result.lezLib.len == 0:
    result.lezLib = repoRoot / "logos-lez-rln-module/rust-lib/target/release/libliblogos_lez_rln_module.dylib"

# --------------------------------------------------- membership event buffer
# The module emits membership_state_changed from its poller thread. The
# callback stays allocation-free: fixed slots under a lock, drained and
# printed from the main poll loop.

const EvSlots = 8
const EvCap = 2048
var
  evLock: Lock
  evBuf: array[EvSlots, array[EvCap, char]]
  evLen: array[EvSlots, int]
  evWrite: int

initLock evLock

proc rlnEmit(name, argsJson: cstring, userData: pointer) {.cdecl.} =
  acquire evLock
  if evWrite < EvSlots and not argsJson.isNil:
    var n = 0
    while n < EvCap - 1 and argsJson[n] != '\0':
      evBuf[evWrite][n] = argsJson[n]
      inc n
    evLen[evWrite] = n
    inc evWrite
  release evLock

proc drainEvents(): seq[string] =
  acquire evLock
  for i in 0 ..< evWrite:
    var s = newString(evLen[i])
    if evLen[i] > 0: copyMem(addr s[0], addr evBuf[i][0], evLen[i])
    result.add s
  evWrite = 0
  release evLock

proc noopEmit(name, argsJson: cstring, userData: pointer) {.cdecl.} =
  discard

# ------------------------------------------------------------------- phases

proc main() =
  let cfg = parseArgs()
  let configPda = cfg.registry.split(':')[2].toLowerAscii

  echo "== nim-poc: RLN stack without logos-core =="
  echo "mode=", cfg.mode, " registry=", cfg.registry
  createDir(cfg.dataDir / "liblogos_rln_module")
  createDir(cfg.dataDir / "lez-rln")

  # 1. lp shim + modules. Context wiring pins both modules' lp owner thread
  #    to this (main) thread; the pool must exist first for the poller's
  #    async calls.
  startLpPool()
  let rln = loadModule("liblogos_rln_module", cfg.rlnLib)
  let lez = loadModule("liblogos_lez_rln_module", cfg.lezLib)
  lpSetLezRln(lez)
  lpSetWalletHandler(walletDispatch)
  lez.setEmit(noopEmit)
  lez.setContext("poc", cfg.dataDir / "lez-rln")
  rln.setEmit(rlnEmit)
  rln.setContext("poc", cfg.dataDir / "liblogos_rln_module")
  echo "modules loaded, lp wire up"

  # 2. Wallet home + wallet. provision_wallet_home writes wallet_config.json
  #    once (never rewrites); storage.json creation stays ours via create_new.
  let home = rln.callTstr("provision_wallet_home", %[$ %*{"sequencer_addr": cfg.sequencer}])
  let configPath = home["config_path"].getStr
  let storagePath = home["storage_path"].getStr
  let statsPath = configPath.parentDir / "statistics.json"
  echo "wallet home: ", home
  let (created, mnemonic) = walletOpenOrCreate(configPath, storagePath, statsPath,
    cfg.walletPassword)
  if created:
    echo "wallet CREATED — mnemonic (store it; without it the wallet is unrecoverable):"
    echo "  ", mnemonic
  else:
    echo "wallet opened from ", storagePath

  # 3. Serial sync to head — a tx from an unsynced wallet is accepted but
  #    never applies, so this must complete before any registration.
  walletSyncToHead()
  let (synced, head) = walletSyncStatus()
  echo "sync status at submit time: synced=", synced, " head=", head

  # 4. start() — configures epoch_size_sec (proof methods are not_ready
  #    without it) and warms the registry's root window in the background.
  let started = rln.callResult("start", %[$ %*{
    "epoch_size_sec": cfg.epochSize, "registries": [cfg.registry]}])
  echo "start: ", started

  # 5. Registry + funding sanity, straight over the wire.
  let params = rln.callResult("get_registry_parameters", %[cfg.registry, cfg.rlnId])
  echo "registry parameters: ", params
  var fundingExists = true
  if cfg.funding.len > 0:
    let bal = lez.callTstr("get_token_balance", %[cfg.funding])
    echo "funding account balance: ", bal
    fundingExists = bal{"exists"}.getBool(false)

  if cfg.mode == "probe":
    echo "PROBE PASS"
    quit(0)

  if cfg.mode == "claim":
    # price_per_unit crosses the wire opaquely (decimal string or number).
    let priceNode = params{"price_per_unit"}
    let price = if priceNode.isNil: 0
                elif priceNode.kind == JString: parseInt(priceNode.getStr)
                else: int(priceNode.getBiggestInt)
    let amount = if cfg.claimAmount > 0: cfg.claimAmount
                 elif price > 0: cfg.rateLimit * price * 2
                 else: quit("registry reports no price_per_unit; pass --claim-amount", 1)
    echo "claiming ", amount, " tokens into ", cfg.funding
    let claim = lez.callTstr("claim_tokens", %*[configPda, cfg.funding, amount])
    echo "claim_tokens: ", claim
    let claimDeadline = getTime() + initDuration(seconds = 180)
    while getTime() < claimDeadline:
      sleep(10_000)
      let bal = lez.callTstr("get_token_balance", %[cfg.funding])
      echo "funding balance: ", bal
      if bal{"exists"}.getBool(false) and parseBiggestInt(bal{"balance"}.getStr("0")) >= amount:
        echo "CLAIM PASS"
        quit(0)
    quit("claim did not land within 180s", 1)

  if not fundingExists:
    quit("funding token account does not exist on-chain — run --mode=claim first", 1)

  # 6. Keystore + register. The reply is the public membership view with
  #    state "pending"; the module's confirmation poller (15s tick) flips it
  #    within its 300s window.
  let unlocked = rln.callTstr("unlock_keystore", %[cfg.password])
  echo "keystore: ", unlocked
  let opts = $ %*{"funding_holding_account_id": cfg.funding}
  let reg = rln.callTstr("register", %*[cfg.registry, cfg.rlnId, cfg.rateLimit, opts])
  echo "register: ", reg
  var state = reg{"state"}.getStr

  # 7. Poll to a terminal state.
  let deadline = getTime() + initDuration(seconds = 420)
  while state == "pending" and getTime() < deadline:
    sleep(15_000)
    for ev in drainEvents():
      echo "event membership_state_changed: ", ev
    let ms = rln.callTstr("get_membership_state", %[cfg.registry, cfg.rlnId])
    state = ms{"state"}.getStr
    echo "membership state: ", ms
  for ev in drainEvents():
    echo "event membership_state_changed: ", ev
  if state notin ["active", "grace_period"]:
    quit("membership did not activate (state=" & state & ")", 1)
  echo "REGISTER PASS (state=", state, ")"

  if cfg.mode == "register":
    quit(0)

  # 8. Proof round-trip. Timestamps cross the wire as strings (lidl: tstr);
  #    verify derives the epoch from the same timestamp the generator bound.
  let ts = $getTime().toUnix
  var proof: JsonNode
  for attempt in 1 .. 6:
    try:
      proof = rln.callResult("generate_proof", %[cfg.registry, cfg.rlnId, cfg.signal, ts])
      break
    except WireError as e:
      # not_ready: the root window is still warming after start().
      if e.class == "not_ready" and attempt < 6:
        echo "generate_proof not_ready (root window warming), retrying..."
        sleep(10_000)
      else:
        raise
  echo "generate_proof: message_id=", proof{"message_id"}, " epoch=", proof{"epoch"}
  let v1 = rln.callResult("verify_proof", %[cfg.registry, cfg.rlnId, cfg.signal, ts, $proof])
  echo "verify_proof: ", v1
  doAssert v1{"verdict"}.getStr == "valid", "expected valid, got " & $v1
  let v2 = rln.callResult("verify_proof", %[cfg.registry, cfg.rlnId, cfg.signal, ts, $proof])
  echo "re-verify (same signal): ", v2
  doAssert v2{"verdict"}.getStr == "duplicate", "expected duplicate, got " & $v2
  echo "PROOF ROUND-TRIP PASS"
  echo "FULL PASS"
  quit(0)

main()
