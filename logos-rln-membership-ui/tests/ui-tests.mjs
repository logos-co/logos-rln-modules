// Hermetic UI smoke test: mkLogosQmlModule auto-detects this file and mounts
// the module in logos-standalone-app under the logos-qt-mcp test framework
// (`nix build .#integration-test`). Backend modules are not loaded, so the
// startup probe's get_memberships errors and the app lands deterministically
// in onboarding mode. This file drives static chrome only: with no
// text-input API, anything behind the password field is out of reach HERE.
// The membership status card, the post-password progression and the
// wizard->card handoff are covered hermetically by flow-tests.mjs, under this
// same nix target. expectTexts
// matches elements regardless of visibility; click() needs a visible element,
// so clickable labels are chosen mutually disjoint across all views.
import { resolve } from "node:path";

// The inspector's default port (3768) is the one a running basecamp holds,
// and the darwin nix sandbox does not isolate the host network — the hermetic
// check would silently connect to basecamp instead of the app under test. Pin
// a non-default port (client and spawned app both read it) before the
// framework loads.
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

test("rln_membership_ui: password, progress and allocator screens exist", async (app) => {
  // Text matching sees invisible items — every screen stays instantiated in
  // the StackLayout. While phases are idle the progress row renders the
  // provisioning placeholder; the allocator step shows its three
  // configuration surfaces (peer id, address, auth vector).
  await app.expectTexts(["Choose a password", "Setting up…",
                         "Register through an allocator", "How the allocator checks you:",
                         // AuthVectorPicker captions carry the selection glyph.
                         "● Open allocator", "○ Keycard", "○ Ethereum key"]);
});

test("rln_membership_ui: advanced keeps the register chrome, plus the allocator toggle", async (app) => {
  await app.click("Advanced setup");
  await app.waitFor(
    async () => {
      await app.expectTexts(["Registry", "Keystore", "Identity", "Registration",
                             "Register membership", "Delegate to an allocator"]);
    },
    { timeout: 10000, interval: 500, description: "advanced mode to activate" }
  );
});

test("rln_membership_ui: advanced payer tab is read-only payer + price", async (app) => {
  await app.click("Payer");
  await app.waitFor(
    async () => {
      await app.expectTexts(["Account", "Native balance", "Refresh", "Registry price",
                             "Price per unit"]);
    },
    { timeout: 10000, interval: 500, description: "payer tab to activate" }
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
