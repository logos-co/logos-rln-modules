## The host's side of the logos-protocol consumer C ABI (`lp_*`) — the part
## of logos-core the RLN modules actually depend on. The module cdylibs are
## linked with `-undefined dynamic_lookup`, so the symbols exported here
## resolve them at dlopen time.
##
## Routing: target "liblogos_lez_rln_module" goes straight into that lib's
## own logos_module_dispatch; target "lez_core" goes to a registered wallet
## handler (wallet_shim.walletDispatch). Everything else is an error reply.
##
## Wire conventions honored (verified against the module sources):
## - lp_invoke's out_result_json must be a JSON value; string-typed method
##   results arrive as a JSON-ENCODED STRING. A module dispatch reply is
##   already in that shape and passes through verbatim; wallet handler
##   replies are string values and get JSON-encoded here.
## - lp_invoke returns 0 (LP_OK) for success; the async callback signals
##   success with ok != 0 (provider.rs:49-53) — note the inverted sense.
## - An lp_invoke_async completion must run AFTER the dispatching handler
##   returned (provider.rs:11-19: register's submit callback takes the store
##   lock the dispatch handler still holds) — completions always run on the
##   worker pool, never inline.
## - Everything handed back through out params is libc-malloc'd;
##   lp_string_free is libc free. One allocator on both sides.

import std/[json, locks]
import module_host

proc c_malloc(size: csize_t): pointer {.importc: "malloc", header: "<stdlib.h>".}
proc c_free(p: pointer) {.importc: "free", header: "<stdlib.h>".}
proc c_strlen(s: cstring): csize_t {.importc: "strlen", header: "<string.h>".}

type
  LpResultCb = proc (ok: cint, json: cstring, userData: pointer) {.cdecl, gcsafe.}

  # The handle lp_client_create returns: just the target module name; all
  # resolution is deferred to invoke time.
  LpClient = object
    target: array[64, char]

  WalletHandler* = proc (meth, argsJson: string): string {.nimcall, gcsafe.}

const
  LezRlnTarget = "liblogos_lez_rln_module"
  WalletTarget = "lez_core"

var
  lezRln: ModuleLib
  lezRlnSet = false
  walletHandler: WalletHandler = nil

proc lpSetLezRln*(lib: ModuleLib) =
  ## Wire before the rln module's set_context (whose on_context_ready makes
  ## the first lp calls) and before starting the pool.
  lezRln = lib
  lezRlnSet = true

proc lpSetWalletHandler*(h: WalletHandler) =
  walletHandler = h

proc dupC(s: string): cstring =
  result = cast[cstring](c_malloc(csize_t(s.len + 1)))
  if s.len > 0:
    copyMem(result, unsafeAddr s[0], s.len)
  cast[ptr char](cast[uint](result) + uint(s.len))[] = '\0'

proc cstrdupC(s: cstring): cstring =
  let n = c_strlen(s)
  result = cast[cstring](c_malloc(n + 1))
  copyMem(result, s, int(n) + 1)

proc routeCall(target, meth, args: string, outRes, outErr: ptr cstring): cint {.gcsafe.} =
  ## Runs on a Nim-owned thread (main, or a pool worker). 0 = success.
  outRes[] = nil
  outErr[] = nil
  {.cast(gcsafe).}:
    if target == LezRlnTarget and lezRlnSet:
      let raw = lezRln.dispatchFn(meth.cstring, args.cstring)
      if raw.isNil:
        outErr[] = dupC($(%*{"message": LezRlnTarget & "." & meth & ": dispatch returned null"}))
        return 1
      outRes[] = cstrdupC(raw)
      lezRln.strFreeFn(raw)
      return 0
    if target == WalletTarget and walletHandler != nil:
      let value = walletHandler(meth, args)
      outRes[] = dupC($(%value))
      return 0
  outErr[] = dupC($(%*{"message": "lp shim: no route for target module '" & target & "'"}))
  return 1

# ------------------------------------------------------------- worker pool
#
# lp_invoke_async may be called from module-owned Rust threads (the
# confirmation poller); the enqueue path therefore touches no Nim heap —
# libc copies plus a pthread lock/cond only. Jobs run on Nim-created worker
# threads. Nesting depth is 2 (a register_member dispatch blocks a worker
# while its nested wallet call runs on another), so 4 workers leave 2x
# headroom for the poller overlapping a register.

const
  PoolSize = 4
  RingCap = 64

type
  Job = object
    target: array[64, char]
    meth: cstring
    args: cstring
    cb: LpResultCb
    userData: pointer

var
  ring: array[RingCap, Job]
  ringHead, ringTail: int
  qLock: Lock
  qCond: Cond
  workers: array[PoolSize, Thread[int]]
  poolStarted = false

proc workerLoop(ix: int) {.thread.} =
  while true:
    var job: Job
    acquire qLock
    while ringHead == ringTail:
      wait(qCond, qLock)
    job = ring[ringHead mod RingCap]
    inc ringHead
    release qLock

    let target = $cast[cstring](addr job.target[0])
    let meth = $job.meth
    let args = $job.args
    c_free(job.meth)
    c_free(job.args)

    var res, err: cstring
    let rc = routeCall(target, meth, args, addr res, addr err)
    # Callback contract: ok != 0 -> json is the result; ok == 0 -> json is
    # the error object. json is only valid for the duration of the call.
    if rc == 0:
      job.cb(1, res, job.userData)
      if not res.isNil: c_free(res)
    else:
      job.cb(0, err, job.userData)
      if not err.isNil: c_free(err)

proc startLpPool*() =
  ## Call once from the main thread before wiring any module context.
  if poolStarted: return
  initLock qLock
  initCond qCond
  for i in 0 ..< PoolSize:
    createThread(workers[i], workerLoop, i)
  poolStarted = true

# ------------------------------------------------------- exported lp_* ABI

proc lp_client_create(target, origin, targetTransport, capTransport: cstring):
    ptr LpClient {.exportc, cdecl, dynlib.} =
  if target.isNil: return nil
  result = cast[ptr LpClient](c_malloc(csize_t sizeof(LpClient)))
  zeroMem(result, sizeof(LpClient))
  let n = min(int(c_strlen(target)), 63)
  copyMem(addr result.target[0], target, n)

proc lp_client_destroy(client: ptr LpClient) {.exportc, cdecl, dynlib.} =
  c_free(client)

proc lp_string_free(s: cstring) {.exportc, cdecl, dynlib.} =
  c_free(s)

proc lp_invoke(client: ptr LpClient, meth, args: cstring, timeoutMs: cint,
               outResult, outError: ptr cstring): cint {.exportc, cdecl, dynlib.} =
  ## Synchronous path. The modules only call this from their lp owner thread
  ## — the thread that ran set_context, i.e. our main thread. In-process the
  ## call completes inline, so timeoutMs needs no enforcement.
  if client.isNil or meth.isNil or args.isNil:
    if not outError.isNil:
      outError[] = dupC("""{"message":"lp_invoke: null argument"}""")
    return -1
  routeCall($cast[cstring](addr client.target[0]), $meth, $args, outResult, outError)

proc lp_invoke_async(client: ptr LpClient, meth, args: cstring, timeoutMs: cint,
                     cb: LpResultCb, userData: pointer): cint {.exportc, cdecl, dynlib.} =
  ## Callable from any thread (module poller threads included): libc-copy
  ## the request, hand it to the pool, never run the callback inline.
  if client.isNil or meth.isNil or args.isNil or cb.isNil:
    return -1
  if not poolStarted:
    return -2
  var job: Job
  job.target = cast[ptr LpClient](client).target
  job.meth = cstrdupC(meth)
  job.args = cstrdupC(args)
  job.cb = cb
  job.userData = userData
  acquire qLock
  if ringTail - ringHead >= RingCap:
    release qLock
    c_free(job.meth)
    c_free(job.args)
    return -3
  ring[ringTail mod RingCap] = job
  inc ringTail
  signal(qCond)
  release qLock
  0

proc lp_token_save(moduleName, token: cstring): cint {.exportc, cdecl, dynlib.} = 0

# Inert remainder of the consumer ABI, exported so a module built against
# the full header still loads.
proc lp_protocol_version(): cstring {.exportc, cdecl, dynlib.} = cstring"0.1.0"
proc lp_protocol_abi_major(): cint {.exportc, cdecl, dynlib.} = 1
proc lp_subscribe(client: ptr LpClient, event: cstring, cb, userData: pointer):
    pointer {.exportc, cdecl, dynlib.} = nil
proc lp_unsubscribe(sub: pointer) {.exportc, cdecl, dynlib.} = discard
proc lp_get_methods(client: ptr LpClient): cstring {.exportc, cdecl, dynlib.} = nil
