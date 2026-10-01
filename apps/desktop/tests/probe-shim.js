/* Test shim for the WebView probe. This file is NOT shipped: it lives
 * outside `ui/`, and `ui/` is exactly what the console serves. A fake
 * bridge next to the real one is a liability, not a fixture.
 *
 * Test shim for the WebView probe. Stands in for Tauri's `__TAURI__` bridge.
 *
 * It exists so the probe can drive the *shipped* `apps/desktop/ui/app.js`
 * unchanged. The alternative was a hand-written copy of the render path, and
 * a copy is exactly the thing that drifts: the probe would keep passing while
 * app.js stopped using textContent. So app.js runs as written, and only the
 * transport underneath it is replaced.
 *
 * The hostile label below is the payload UAT-019 names. It is delivered the
 * way a broker would deliver it: as a JSON string value, never as markup.
 */
"use strict";

window.__asv_pwned = undefined;
window.__asv_invocations = [];

const HOSTILE =
  '<img src=x onerror="window.__asv_pwned=1">' +
  '"><script>window.__asv_pwned=1<\/script>' +
  '<svg onload="window.__asv_pwned=1">';

const CANARY = "ASV-SECRET-CANARY-4b1e77aa";

/* The shim answers the transport, not the policy.
 *
 * The shipped app.js routes every console command through a single
 * `dispatch_console` invoke, with the command name inside the payload. That
 * is the design — one entry point whose table the core's registry decides —
 * so the shim has to unwrap it to answer per command. Recording the outer
 * name too is deliberate: `cmds=dispatch_console,dispatch_console` is the
 * evidence that the console really did ask twice, through the one door.
 */
const HOSTILE_LABEL =
  '<img src=x onerror="window.__asv_pwned=1">' +
  '"><script>window.__asv_pwned=1<\/script>' +
  '<svg onload="window.__asv_pwned=1">';

const ITEMS = [
  {
    id: "cred-1",
    label: HOSTILE_LABEL,
    provider: "postgres",
    // NonExportable: the console must offer neither copy nor reveal.
    exportability: "non_exportable",
    has_agent_access: true,
  },
  {
    id: "cred-2",
    label: "prod-db",
    provider: "postgres",
    // HumanOnly: reveal is offered, and re-auth is the core's business.
    exportability: "human_only",
    has_agent_access: true,
  },
];

function answer(command) {
  if (command === "list_credentials") return { items: ITEMS };
  if (command === "begin_reveal") return { error: "probe: no broker" };
  return { refused: "unhandled in the shim" };
}

window.__TAURI__ = {
  core: {
    invoke: function (command, args) {
      window.__asv_invocations.push(command);
      if (command !== "dispatch_console") {
        return Promise.resolve(answer(command));
      }
      const inner = (args && args.command) || "";
      window.__asv_invocations.push(inner);
      return Promise.resolve(answer(inner));
    },
  },
};
