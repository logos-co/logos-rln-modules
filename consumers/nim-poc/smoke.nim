## Go/no-go gate for the whole approach: proves that
## 1. both module cdylibs dlopen side by side (identical export sets, RTLD_LOCAL),
## 2. their undefined lp_* symbols resolve against this executable's exports
##    (set_context fires on_context_ready -> lp_client_create; under macOS
##    chained fixups an unresolvable dynamic_lookup import fails the dlopen
##    itself),
## 3. a real dispatch works (unlock_keystore writes the keystore under the
##    persistence dir),
## 4. the full nested lp chain runs: rln get_valid_roots -> lp_invoke ->
##    lez-rln dispatch -> lp_invoke("lez_core") -> wallet stub -> error
##    surfaces back as an in-band wire error (NOT a routing error).
##
## Usage: smoke <rln.dylib> <lez_rln.dylib> <data-dir>

import std/[json, os, strutils]
import module_host, lp_shim

proc noopEmit(name, argsJson: cstring, userData: pointer) {.cdecl.} =
  discard

proc main() =
  if paramCount() != 3:
    quit("usage: smoke <rln.dylib> <lez_rln.dylib> <data-dir>", 2)
  let rlnPath = paramStr(1)
  let lezPath = paramStr(2)
  let dataDir = paramStr(3)
  createDir(dataDir / "liblogos_rln_module")
  createDir(dataDir / "lez-rln")

  startLpPool()

  let rln = loadModule("liblogos_rln_module", rlnPath)
  let lez = loadModule("liblogos_lez_rln_module", lezPath)
  echo "loaded rln module: ", rln.getMethods().len, " methods"
  echo "loaded lez-rln module: ", lez.getMethods().len, " methods"

  lpSetLezRln(lez)
  # No wallet handler on purpose: the lez_core leg must fail cleanly.

  lez.setEmit(noopEmit)
  lez.setContext("smoke", dataDir / "lez-rln")
  rln.setEmit(noopEmit)
  rln.setContext("smoke", dataDir / "liblogos_rln_module")
  echo "set_context OK on both (lp_client_create resolved from host executable)"

  let unlocked = rln.callTstr("unlock_keystore", %["smoke-pass"])
  doAssert unlocked{"unlocked"}.getBool, "unlock_keystore: " & $unlocked
  echo "unlock_keystore: ", unlocked

  let registry = "logos:smoke:" & repeat("00", 32)
  try:
    let roots = rln.callTstr("get_valid_roots", %[registry])
    quit("unexpected get_valid_roots success (no wallet!): " & $roots, 1)
  except WireError as e:
    doAssert "no route" notin e.msg,
      "lp chain broke at the shim routing layer: " & e.msg
    echo "get_valid_roots failed in-band as expected (class=", e.class,
      "): full lp chain rln -> lez-rln -> lez_core stub exercised"

  echo "SMOKE PASS"

main()
