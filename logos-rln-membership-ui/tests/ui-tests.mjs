// Hermetic UI smoke test: mkLogosQmlModule auto-detects this file and mounts
// the module in logos-standalone-app under the logos-qt-mcp test framework
// (`nix build .#integration-test`). Backend modules are NOT loaded here, so
// the startup probe's get_memberships errors immediately -> the app lands
// deterministically in onboarding mode. Hermetically untestable (covered by
// the live basecamp smoke instead): the membership status card, step
// progression past the password step (no text-input API), and the
// wizard->card completion handoff. Note expectTexts matches
// elements regardless of visibility; click() needs a visible element — the
// wizard/card/advanced clickable labels are chosen mutually disjoint and
// disjoint from every string in the legacy views.
import { resolve } from "node:path";

// The inspector defaults to port 3768 — the SAME port a running basecamp's
// inspector holds, and the darwin nix sandbox does not isolate the host
// network, so the hermetic check would silently connect to basecamp's UI
// instead of the app under test. Pin a non-default port (framework client
// and the spawned app both read this env var) before the framework loads.
process.env.QML_INSPECTOR_PORT = process.env.QML_INSPECTOR_PORT || "13768";

// CI sets LOGOS_QT_MCP; interactively: nix build .#test-framework -o result-mcp
const root = process.env.LOGOS_QT_MCP || new URL("../result-mcp", import.meta.url).pathname;
const { test, run } = await import(resolve(root, "test-framework/framework.mjs"));

test("rln_membership_ui: loads into onboarding with the headline and CTA", async (app) => {
  await app.waitFor(
    async () => {
      await app.expectTexts(["Register to participate in p2p messaging and more!",
                             "Get started", "Advanced setup"]);
    },
    { timeout: 15000, interval: 500, description: "onboarding to load" }
  );
});

test("rln_membership_ui: password screen and progress bar exist", async (app) => {
  // findByProperty is exact-match and sees invisible items — every screen
  // stays instantiated in the StackLayout. The morphing progress row shows
  // its first segment's label ("Syncing…") by default while phases are idle
  // (only the active/errored segment's label renders at a time now).
  await app.expectTexts(["Choose a password", "Syncing with Logos Blockchain..."]);
});

test("rln_membership_ui: advanced keeps the legacy register chrome", async (app) => {
  await app.click("Advanced setup");
  await app.waitFor(
    async () => {
      await app.expectTexts(["Registry", "Keystore", "Identity", "Registration",
                             "Register membership"]);
    },
    { timeout: 10000, interval: 500, description: "advanced mode to activate" }
  );
});

test("rln_membership_ui: advanced wallet tab keeps the legacy funding chrome", async (app) => {
  await app.click("Wallet");
  await app.waitFor(
    async () => {
      await app.expectTexts(["Use basecamp wallet", "Sequencer",
                             "Advanced: use existing wallet files",
                             "Open wallet", "Create wallet",
                             "Sync to head", "Faucet claim", "Claim into fresh holding"]);
    },
    { timeout: 10000, interval: 500, description: "wallet tab to activate" }
  );
});

test("rln_membership_ui: exit advanced re-probes back into onboarding", async (app) => {
  await app.click("Exit advanced");
  await app.waitFor(
    async () => {
      await app.expectTexts(["Register to participate in p2p messaging and more!",
                             "Get started"]);
    },
    { timeout: 10000, interval: 500, description: "onboarding to return" }
  );
});

run();
