// The console front-end.
//
// One rule governs this file: **a value that came from the broker is written
// with `textContent`, never with `innerHTML`.** That is not a style
// preference. `asv-operator-core`'s `SafeText` escapes on the Rust side, but
// escaping that the renderer then undoes is the same as no escaping, and
// `textContent` cannot undo anything: there is no parsing step for a hostile
// string to escape from.
//
// UAT-019 injects a label that tries all of the usual exits — an `onerror`
// handler, a script tag, an attribute breakout. Each of them is inert here
// because none of them is ever handed to an HTML parser.

"use strict";

const { invoke } = window.__TAURI__.core;

/** Ask the shell to run a command. */
function dispatch(command, payload) {
  return invoke("dispatch_console", { command, payload: payload ?? null });
}

/** Write untrusted text into an element. The only way text gets on screen. */
function setText(node, text) {
  node.textContent = text == null ? "" : String(text);
}

/**
 * UAT-020: a `NonExportable` credential offers no copy and no reveal.
 *
 * The buttons are not created. A disabled button is still a button, and a
 * disabled button is one click away from being re-enabled by a later commit;
 * an absent one is not. The Rust side decides which of these to render — this
 * function only builds what it is told to build.
 */
function renderActions(cell, item) {
  // These are the *wire* values. `Exportability` carries
  // `#[serde(rename_all = "snake_case")]`, so the broker sends
  // `human_only`, not `HumanOnly`. Comparing against the Rust spelling was a
  // silent failure: neither branch matched, no button was built, and a
  // HumanOnly credential looked exactly like a NonExportable one. The
  // WebView probe found it by counting buttons, not by reading this comment.
  const permitted =
    item.exportability === "human_only" || item.exportability === "exportable";

  if (!permitted) {
    setText(cell, "—");
    return;
  }
  if (item.exportability === "human_only") {
    const button = document.createElement("button");
    button.type = "button";
    setText(button, "Reveal…");
    button.addEventListener("click", () => beginReveal(item.id));
    cell.appendChild(button);
    return;
  }
  const button = document.createElement("button");
  button.type = "button";
  setText(button, "Export");
  button.addEventListener("click", () => beginReveal(item.id));
  cell.appendChild(button);
}

/** Render one credential row. */
function renderRow(tbody, item) {
  const row = document.createElement("tr");

  for (const key of ["label", "provider", "exportability"]) {
    const cell = document.createElement("td");
    setText(cell, item[key]);
    row.appendChild(cell);
  }

  const access = document.createElement("td");
  setText(access, item.has_agent_access ? "granted" : "none");
  row.appendChild(access);

  const actions = document.createElement("td");
  renderActions(actions, item);
  row.appendChild(actions);

  tbody.appendChild(row);
}

/** Start the reveal *flow*. Not the reveal itself — that needs re-auth. */
async function beginReveal(id) {
  const result = await dispatch("begin_reveal", { id });
  setText(document.getElementById("status"), `reveal requested for ${id}`);
  return result;
}

/** Load and render. */
async function refresh() {
  const status = document.getElementById("status");
  const tbody = document.querySelector("#credentials tbody");
  tbody.textContent = "";

  const result = await dispatch("list_credentials");
  if (result && result.refused) {
    setText(status, result.refused);
    return;
  }
  const items = (result && result.items) || [];
  for (const item of items) {
    renderRow(tbody, item);
  }
  setText(status, `${items.length} credential(s)`);
}

window.addEventListener("DOMContentLoaded", () => {
  refresh();
});
