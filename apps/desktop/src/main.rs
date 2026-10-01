// The only file in this crate that imports Tauri.
//
// That placement is deliberate: `surface.rs` and `backend.rs` are the parts
// that decide what the console may show, and they compile and test with no
// Tauri and no WebView. If the security-relevant logic needed an `AppHandle`,
// it could only be tested on a machine with a display.
//
// The whole file is behind the `gui` feature so that `cargo test` on a
// headless machine does not have to build the WebView at all.

#![cfg(feature = "gui")]

use asv_desktop::disconnected_console;

/// One Tauri command. Its entire body is a dispatch.
///
/// The name arrives as a `String` from the WebView and is matched by the
/// core's vocabulary, not by this match arm: the `match` below only routes
/// *already-resolved* names to their handler, and a name that is not a
/// capability never gets this far, because `dispatch` refuses it first.
///
/// The `#[tauri::command]` attribute generates the `macros::` namespace, so
/// the frontend calls `macros::dispatch_console`.
#[tauri::command]
fn dispatch_console(
    state: tauri::State<'_, asv_desktop::surface::Console>,
    command: String,
    payload: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    // A malformed payload is turned into a parse *error value* rather than
    // being deserialised here, so that the refusal order the surface
    // guarantees — name, then authorisation, then argument — is the order
    // that actually runs.
    let args = match payload {
        Some(value) => Ok(value),
        None => Ok(serde_json::Value::Null),
    };

    match state.dispatch(&command, args) {
        asv_desktop::surface::Outcome::Ok { payload } => Ok(payload),
        // A refusal is not an error: it is a normal, expected answer, and the
        // frontend renders it as such. Turning it into a `Err` would make the
        // WebView treat "you may not do that" as a malfunction.
        other => Ok(serde_json::json!({ "refused": format!("{other:?}") })),
    }
}

fn main() {
    tauri::Builder::default()
        .manage(disconnected_console())
        .invoke_handler(tauri::generate_handler![dispatch_console])
        .run(tauri::generate_context!())
        .expect("the operator console failed to start");
}
