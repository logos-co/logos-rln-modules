## Minimal host for logos modules loaded outside logos-core.
##
## Loads a module cdylib (a rust-lib built with `cargo rustc --crate-type
## cdylib` and, on macOS, `-Wl,-undefined,dynamic_lookup`) and resolves the
## `logos_module_*` C ABI via dlsym per handle — both RLN modules export the
## same symbol names, so nothing may be resolved globally.
##
## Wire: positional JSON-array args in, JSON out. Two reply dialects
## (docs/wire-binding.md in logos-rln-module):
## - `tstr` methods: dispatch returns a JSON *string* whose contents are the
##   module's compact JSON. The membership module reports failures in-band as
##   {"error":{"class","kind","message"}}; the lez-rln module returns "" on
##   failure.
## - `result` methods: dispatch returns a JSON object
##   {"success": bool, "value": ..., "error": <json-encoded error or null>}.

import std/[dynlib, json]

type
  EmitCb* = proc (name: cstring, argsJson: cstring, userData: pointer) {.cdecl.}
  DispatchFn = proc (m: cstring, a: cstring): cstring {.cdecl.}
  GetMethodsFn = proc (): cstring {.cdecl.}
  SetContextFn = proc (modulePath, instanceId, persistencePath: cstring) {.cdecl.}
  SetEmitFn = proc (cb: EmitCb, userData: pointer) {.cdecl.}
  StrFreeFn = proc (s: cstring) {.cdecl.}

  ModuleLib* = object
    name*: string
    handle: LibHandle
    dispatchFn*: DispatchFn
    getMethodsFn: GetMethodsFn
    setContextFn: SetContextFn
    setEmitFn: SetEmitFn
    strFreeFn*: StrFreeFn

  ModuleError* = object of CatchableError
  WireError* = object of ModuleError
    class*: string
    kind*: string

proc loadModule*(name, path: string): ModuleLib =
  result.name = name
  result.handle = loadLib(path, globalSymbols = false)
  if result.handle.isNil:
    raise newException(ModuleError, name & ": failed to dlopen " & path)
  template sym(n: string, T: typedesc): untyped =
    block:
      let p = symAddr(result.handle, n)
      if p.isNil:
        raise newException(ModuleError, name & ": missing symbol " & n)
      cast[T](p)
  result.dispatchFn = sym("logos_module_dispatch", DispatchFn)
  result.getMethodsFn = sym("logos_module_get_methods", GetMethodsFn)
  result.setContextFn = sym("logos_module_set_context", SetContextFn)
  result.setEmitFn = sym("logos_module_set_emit_callback", SetEmitFn)
  result.strFreeFn = sym("logos_module_string_free", StrFreeFn)

proc setEmit*(lib: ModuleLib, cb: EmitCb, userData: pointer = nil) =
  lib.setEmitFn(cb, userData)

proc setContext*(lib: ModuleLib, instanceId, persistencePath: string) =
  ## Fires on_context_ready inside the module (which pins its lp owner
  ## thread to the calling thread) — call from the main thread only, after
  ## the lp shim is ready to serve lp_client_create.
  lib.setContextFn(lib.name.cstring, instanceId.cstring, persistencePath.cstring)

proc getMethods*(lib: ModuleLib): JsonNode =
  let raw = lib.getMethodsFn()
  if raw.isNil:
    raise newException(ModuleError, lib.name & ": get_methods returned null")
  result = parseJson($raw)
  lib.strFreeFn(raw)

proc dispatchRaw*(lib: ModuleLib, meth: string, args: JsonNode): string =
  ## One dispatch round-trip; returns the outer JSON text verbatim.
  ## NULL (unknown method / structural failure) raises.
  let raw = lib.dispatchFn(meth.cstring, cstring($args))
  if raw.isNil:
    raise newException(ModuleError, lib.name & "." & meth & ": dispatch returned null")
  result = $raw
  lib.strFreeFn(raw)

proc raiseWire(lib: ModuleLib, meth: string, error: JsonNode) =
  let e = newException(WireError,
    lib.name & "." & meth & " failed: " & $error)
  if error.kind == JObject:
    e.class = error{"class"}.getStr("")
    e.kind = error{"kind"}.getStr("")
  raise e

proc callTstr*(lib: ModuleLib, meth: string, args: JsonNode): JsonNode =
  ## A `tstr`-dialect call: unwraps the double encoding, raises WireError on
  ## an in-band {"error":...} (membership module) or an empty reply (the
  ## lez-rln module's ""-means-failure convention).
  let outer = parseJson(dispatchRaw(lib, meth, args))
  if outer.kind != JString:
    raise newException(ModuleError,
      lib.name & "." & meth & ": expected string reply, got: " & $outer)
  let inner = outer.getStr
  if inner.len == 0:
    raise newException(ModuleError, lib.name & "." & meth & ": provider failure (empty reply)")
  result = parseJson(inner)
  if result.kind == JObject and result.hasKey("error"):
    raiseWire(lib, meth, result["error"])

proc callResult*(lib: ModuleLib, meth: string, args: JsonNode): JsonNode =
  ## A `result`-dialect call: unwraps {"success","value","error"}; the error
  ## arm is a JSON-encoded {"class","kind","message"} object.
  let outer = parseJson(dispatchRaw(lib, meth, args))
  if outer.kind != JObject or not outer.hasKey("success"):
    raise newException(ModuleError,
      lib.name & "." & meth & ": expected result envelope, got: " & $outer)
  if not outer["success"].getBool:
    let errText = outer{"error"}.getStr("")
    var errNode: JsonNode
    try:
      errNode = parseJson(errText)
    except CatchableError:
      errNode = %errText
    raiseWire(lib, meth, errNode)
  outer{"value"}
