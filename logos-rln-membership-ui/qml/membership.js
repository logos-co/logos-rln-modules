// Shared plumbing for the RLN membership GUI: logos-bridge reply parsing,
// error rendering, and small formatting helpers. Wire shapes come from
// rust-lib/liblogos_rln_module.lidl (failures {"error":{"class":…,"kind":…,
// "message":…}}) and liblogos_lez_rln_module (""-on-error convention).
.pragma library

var RLN_MODULE = "liblogos_rln_module";
var LEZ_RLN_MODULE = "liblogos_lez_rln_module";
var WALLET_MODULE = "lez_core";
// Gifter path (alternative registration) only — unused by the wallet path:
// rln_gifter_module runs the gifter protocol and relays libp2p_module calls;
// keycard_capture_module does the in-process PC/SC Keycard IDENTIFY capture;
// libp2p_module provides the node the gifter dials through.
var LIBP2P_MODULE = "libp2p_module";
var GIFTER_MODULE = "rln_gifter_module";
var CAPTURE_MODULE = "keycard_capture_module";

// testnet-shrink-verify registry (CAIP-10; descriptor under
// logos-lez-rln deployments/testnet-shrink-verify/) — the GUI's prefill,
// freely editable. The previous shared-faucet instance died with the
// testnet reset; its config account no longer exists on-chain.
var TESTNET_REGISTRY_ID =
    "logos:testnet:2fdff09aec02fe4f03157c77bddfa36bd3fd4c8ac546558daf4fe174647e5542";

var RATE_LIMIT_MIN = 100;
var RATE_LIMIT_MAX = 600;
var RATE_LIMIT_DEFAULT = 300;

// register / get_membership_state / select_membership take a MembershipScope
// (registry_id + rln_identifier). This GUI is a management tool, not an RLN
// application, so it passes a fixed default rln_identifier; an application
// generating proofs passes its own 32-byte scope key.
var DEFAULT_RLN_ID =
    "0000000000000000000000000000000000000000000000000000000000000000";

// The single UI-scale knob: host Theme singletons can't be mutated, so token
// values are multiplied at usage sites via sc(). The values scale (no rendered
// transform), so text stays crisp; results round to integer pixels.
var UI_SCALE = 2;

function sc(x) {
    return Math.round(x * UI_SCALE);
}

// The deployed testnet sequencer (testnet-shrink-verify deployment)
// — prefill for provision_wallet_home's wallet_config.json.
var TESTNET_SEQUENCER_ADDR = "https://testnet.lez.logos.co/";

// The wallet's open/create_new take a statistics_path since LEZ v0.2.2
// (sequencer-latency stats live beside the wallet). Derived from the storage
// path so it works for provision_wallet_home's layout and hand-entered
// Advanced paths alike; the file need not pre-exist.
function statsPathFor(storagePath) {
    var i = storagePath.lastIndexOf("/");
    return (i >= 0 ? storagePath.substring(0, i + 1) : "") + "statistics.json";
}

// StepGifter prefills, both freely editable. Defaults point at the local dev
// gifter (tools/run-local-gifter.sh), whose fixed node key keeps this peerId
// stable across restarts.
var GIFTER_PEER_ID_DEFAULT = "16Uiu2HAm8KkYKyhBK5f8ZcSDJP947bxCqVRRbzP8DKDigqePtX2Y";
var GIFTER_MULTIADDR_DEFAULT = "/ip4/127.0.0.1/tcp/9000";

// The app's own libp2p node, brought up only to dial the gifter: a direct
// protocol dial to a known peer needs no gossipsub/kad/discovery. A plain
// object — libp2pCall JSON.stringifies it into createNode's single string arg.
var LIBP2P_NODE_CONFIG = {
    addrs: ["/ip4/127.0.0.1/tcp/0"],
    transport: "tcp",
    maxConnections: 16,
    maxInConnections: 8,
    maxOutConnections: 8,
    maxConnsPerPeer: 1,
    mountGossipsub: false,
    mountKad: false,
    mountServiceDiscovery: false
};

// libp2p_module's C++ methods return a StdLogosResult that marshals to `null`
// through the QML bridge, so every libp2p call is relayed through
// rln_gifter_module.libp2p_call, which returns {success,value,error} as a
// (possibly double-encoded) JSON string. Never route through parseReply: its
// empty-"error" rule would flag a successful reply (error:"") as a failure.
function parseLibp2pReply(payload) {
    var v;
    try { v = JSON.parse(payload); } catch (e) { return { error: "unparseable libp2p reply: " + payload }; }
    if (typeof v === "string") {
        try { v = JSON.parse(v); } catch (e) { return { error: v }; }
    }
    if (v === null || typeof v !== "object")
        return { error: "unexpected libp2p reply: " + payload };
    return v;
}

// A libp2p relay reply carries an error only when its `error` field is a
// NON-empty string (success replies carry error:"").
function libp2pError(r) {
    return (r && typeof r.error === "string" && r.error !== "") ? r.error : "";
}

function mkError(kind, message) {
    return { error: { kind: kind, message: message } };
}

// Normalize bridge replies. LogosQmlBridge double-encodes tstr replies;
// bridge-level failures arrive as plain objects with a STRING error field;
// the wallet module returns bare scalars and raw strings, with "" signaling
// failure. JSON-object replies pass through, scalars and raw strings become
// {value:…}, and every failure becomes {error:{kind,message}}.
function parseReply(payload) {
    var v;
    try { v = JSON.parse(payload); } catch (e) {
        return mkError("bad_reply", "unparseable reply: " + payload);
    }
    if (typeof v === "string") {
        if (v === "")
            return mkError("empty_reply",
                           "the module returned \"\" (its error convention)");
        try {
            var inner = JSON.parse(v);
            if (inner !== null && typeof inner === "object")
                v = inner;
            else
                return { value: v };
        } catch (e) {
            return { value: v };
        }
    }
    if (typeof v === "number" || typeof v === "boolean")
        return { value: v };
    if (v === null || typeof v !== "object")
        return mkError("bad_reply", "unexpected reply shape: " + payload);
    if (typeof v.error === "string")
        return mkError("bridge_failure", v.error);
    return v;
}

// Async call through the injected logos bridge; cb always receives a
// normalized object (see parseReply), never throws. timeoutMs overrides the
// bridge's 30s client-side timeout — pass 0 to disable it for calls that
// legitimately run for minutes (sync_to_block on a fresh wallet).
//
// Numeric args are coerced with `| 0`: QML sends a JS number as QVariant(int)
// only while V4 has it int32-tagged; arithmetic and parseInt results arrive
// as QVariant(double), which the Rust modules' dispatch (serde_json as_i64(),
// None on a float) silently turns into 0 — a zero-token claim, a zero
// rate_limit. All lidl numeric params here are ints below the int32 ceiling.
function call(bridge, module, method, args, cb, timeoutMs) {
    if (!bridge) {
        cb(mkError("no_bridge",
                   "logos bridge unavailable — run inside basecamp or logos-standalone-app"));
        return;
    }
    var wireArgs = args.map(function (a) {
        return typeof a === "number" ? (a | 0) : a;
    });
    bridge.callModuleAsync(module, method, wireArgs, function (payload) {
        cb(parseReply(payload));
    }, timeoutMs === undefined ? 30000 : timeoutMs);
}

// --- events (push channel; see module docs/wire-binding.md "Events") ------
// membership_state_changed fires when a membership's registry-observed state
// changes; positional args
// [registry_id, rln_identifier, membership_hash, state, previous]. It rides
// LogosQmlBridge's moduleEventReceived signal — decode it directly, never
// through parseReply. Optional per the spec: a host predating onModuleEvent
// never fires it, so every caller keeps its poll fallback.
var MEMBERSHIP_STATE_CHANGED = "membership_state_changed";

// Arm a module-event subscription on the bridge. Returns false when the host
// bridge predates onModuleEvent; callers keep their poll fallback either way.
function armModuleEvent(bridge, module, eventName) {
    var armed = !!bridge && typeof bridge.onModuleEvent === "function"
        && bridge.onModuleEvent(module, eventName) === true;
    if (!armed)
        console.log(eventName + ": events not armed on this bridge — falling back to poll-only cadence");
    return armed;
}

// Decode a membership_state_changed payload (positional array) into a named
// object, null when the shape is not as documented.
function decodeMembershipStateChanged(data) {
    if (!Array.isArray(data) || data.length < 5)
        return null;
    return {
        registry_id: String(data[0]),
        rln_identifier: String(data[1]),
        membership_hash: String(data[2]),
        state: String(data[3]),
        previous: String(data[4])
    };
}

// One-line hints for the error kinds a user can act on (the lidl's kinds
// plus the local ones minted by parseReply/call above).
var ERROR_HINTS = {
    locked: "Unlock the keystore with your password first.",
    bad_password: "The password does not match the existing keystore.",
    provider_failure: "Registry provider failed — check that the rln module is loaded, the wallet is open, and the network is reachable.",
    no_usable_membership: "No active or grace-period membership to select.",
    ambiguous_selection: "More than one candidate — pass a selector.",
    invalid_argument: "Check the field formats (hex lengths, CAIP-10 registry id, rate limit bounds).",
    bridge_failure: "The module is not loaded or connected in this host.",
    no_bridge: "Not running inside a Logos host application.",
    empty_reply: "The module reported a failure — is the wallet open and synced, and the network reachable?",
    keychain_unavailable: "Couldn't reach the OS keychain — enter your password to continue."
};

function errorText(err) {
    var kind = err && err.kind ? err.kind : "unknown";
    var msg = err && err.message ? err.message : "";
    var hint = ERROR_HINTS[kind];
    return kind + ": " + msg + (hint ? "\n" + hint : "");
}


function truncateHex(hex, head, tail) {
    if (!hex) return "";
    var h = hex.indexOf("0x") === 0 ? hex.slice(2) : hex;
    if (h.length <= head + tail + 1) return h;
    return h.slice(0, head) + "…" + h.slice(h.length - tail);
}


function formatTimestamp(secs) {
    if (!secs) return "";
    return new Date(secs * 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

// A membership row's `tx_result` is the raw register_member wire reply
// recorded at registration: a JSON STRING of
//   {"leaf_index":N,"payment_definition":"<hex>","tx_result":"<json string>"}
// whose inner `tx_result` is itself JSON-encoded — two JSON.parse steps.
// Absent for memberships adopted via the already-registered pre-check. Any
// absence / "" / malformed shape returns null (the caller hides the section);
// success returns {hash, success, error, paymentDefinition}.
function parseTxResult(raw) {
    if (raw === undefined || raw === null || raw === "")
        return null;
    try {
        var outer = typeof raw === "string" ? JSON.parse(raw) : raw;
        if (!outer || typeof outer !== "object")
            return null;
        var inner = outer.tx_result;
        if (typeof inner === "string" && inner !== "")
            inner = JSON.parse(inner);
        if (!inner || typeof inner !== "object")
            return null;
        var hash = typeof inner.tx_hash === "string" ? inner.tx_hash : "";
        var err = typeof inner.error === "string" ? inner.error : "";
        if (hash === "" && inner.success === undefined && err === "")
            return null;
        return {
            hash: hash,
            success: inner.success === true,
            error: err,
            paymentDefinition: typeof outer.payment_definition === "string" ? outer.payment_definition : ""
        };
    } catch (e) {
        return null;
    }
}

// The CAIP-10 registry id's third segment doubles as the registry's config
// account id (64 hex) — the rln module's resolve_account_id passes 64-hex
// through verbatim, so claim/bounds calls can use it directly.
function registryConfigHex(registryId) {
    var parts = registryId.split(":");
    if (parts.length !== 3) return "";
    var h = parts[2].toLowerCase();
    return /^[0-9a-f]{64}$/.test(h) ? h : "";
}

// Suggested faucet claim for one registration: rate × price_per_unit × 1.2
// slack, ceiled to an int (price_per_unit arrives as a decimal string).
// Returns NaN when the price is non-numeric — the caller must surface that
// rather than claim 0 tokens (a 0-token claim is accepted and silently
// dropped into the 180s timeout).
function suggestedClaimAmount(rate, priceStr) {
    var price = parseInt(priceStr, 10);
    if (!(price > 0))
        return NaN;
    return Math.ceil(rate * price * 1.2);
}

// States that land the user on the status card. Pending counts so a relaunch
// mid-confirmation resumes on the card; it joins select()'s usable set
// (active/grace_period) within the 300s confirmation window or flips to failed.
function isUsableState(s) {
    return s === "pending" || s === "active" || s === "grace_period";
}

// Terminal states the user can act on by re-registering (the detail card's
// Re-register affordance).
function isRenewable(s) {
    return s === "failed" || s === "expired" || s === "erased";
}

// Sort rank for the memberships list, best state first; unknown states sort
// last.
function stateRank(s) {
    var order = ["active", "grace_period", "pending", "expired", "failed", "erased"];
    var i = order.indexOf(s);
    return i < 0 ? order.length : i;
}

// A wire number that may be absent (pending memberships have no leaf/rate
// yet): render a placeholder instead of the literal "undefined".
function fmtOptionalNum(v) {
    return (v === undefined || v === null) ? "—" : String(v);
}

// Transport/host/sequencer flakiness kinds — the rln and wallet modules
// intermittently drop responses over QtRO under load, surfacing as these
// kinds; retrying self-heals. Every other kind (bad_password, locked,
// invalid_argument, …) is deterministic and must surface immediately.
var TRANSIENT_ERROR_KINDS = {
    bridge_failure: true,
    timeout: true,
    empty_reply: true,
    bad_reply: true,
    provider_failure: true
};

function isTransientError(kind) {
    return TRANSIENT_ERROR_KINDS[kind] === true;
}

// Deterministic petname for a public commitment — a display alias, never an
// identifier. Three 64-word lists (adjective-gem-animal) indexed by pairs of
// commitment bytes give 64^3 = 262,144 combinations; the same commitment
// always yields the same name.
var PETNAME_ADJECTIVES = [
    "amber", "brave", "calm", "daring", "eager", "fabled", "gentle", "hardy",
    "ideal", "jolly", "keen", "lucid", "merry", "noble", "opal", "proud",
    "quiet", "regal", "swift", "true", "usual", "vivid", "witty", "zealous",
    "arctic", "bold", "cosmic", "dawn", "elder", "fresh", "grand", "hidden",
    "iron", "jade", "kind", "lunar", "mellow", "north", "olive", "prime",
    "quick", "royal", "solar", "tidal", "umbral", "vernal", "warm", "young",
    "azure", "bright", "clever", "deep", "epic", "fleet", "glad", "humble",
    "inner", "just", "loyal", "mild", "nimble", "open", "pure", "rapid"
];
var PETNAME_GEMS = [
    "amethyst", "beryl", "citrine", "diamond", "emerald", "flint", "garnet",
    "halite", "iolite", "jasper", "kunzite", "lapis", "moonstone", "nacre",
    "onyx", "pearl", "quartz", "ruby", "sapphire", "topaz", "ulexite", "verdite",
    "willow", "xenolith", "yttria", "zircon", "agate", "bronze", "coral",
    "dolomite", "ember", "feldspar", "gold", "hematite", "indigo", "jet",
    "kyanite", "larimar", "malachite", "nickel", "opal", "peridot", "quicksilver",
    "rhodium", "silver", "tourmaline", "umber", "violet", "watermelon", "xanthite",
    "yellowstone", "zoisite", "amber", "cobalt", "crimson", "cyan", "gilt",
    "ivory", "lilac", "magenta", "ochre", "saffron", "teal", "vermilion"
];
var PETNAME_ANIMALS = [
    "aardvark", "badger", "cheetah", "dolphin", "eagle", "falcon", "gecko",
    "heron", "ibis", "jaguar", "kestrel", "lynx", "marten", "narwhal", "otter",
    "puffin", "quail", "raven", "seal", "tapir", "urial", "vixen", "walrus",
    "yak", "zebra", "antelope", "bison", "condor", "dingo", "egret", "ferret",
    "gazelle", "hawk", "impala", "jackal", "koala", "lemur", "mongoose", "newt",
    "osprey", "panda", "quokka", "robin", "stoat", "toucan", "urchin", "viper",
    "wombat", "yabby", "zorilla", "alpaca", "beaver", "crane", "deer", "elk",
    "finch", "gopher", "hare", "iguana", "jay", "kite", "manatee", "orca"
];

function petByte(hex, i) {
    return parseInt(hex.substr(i * 2, 2), 16) || 0;
}

function petname(commitmentHex) {
    if (!commitmentHex) return "";
    var h = commitmentHex.indexOf("0x") === 0 ? commitmentHex.slice(2) : commitmentHex;
    h = h.toLowerCase();
    if (!/^[0-9a-f]{12,}$/.test(h)) return "";
    var adj = PETNAME_ADJECTIVES[(petByte(h, 0) * 256 + petByte(h, 1)) % PETNAME_ADJECTIVES.length];
    var gem = PETNAME_GEMS[(petByte(h, 2) * 256 + petByte(h, 3)) % PETNAME_GEMS.length];
    var ani = PETNAME_ANIMALS[(petByte(h, 4) * 256 + petByte(h, 5)) % PETNAME_ANIMALS.length];
    return adj + "-" + gem + "-" + ani;
}

function rateText(rate) {
    return (rate === undefined || rate === null) ? "— msg/epoch" : String(rate) + " msg/epoch";
}
