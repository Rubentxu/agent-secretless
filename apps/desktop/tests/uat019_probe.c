/* UAT-019 and UAT-020 against the real render engine.
 *
 * This is a WebKitGTK program, not a Tauri test, and the choice is the whole
 * point. Tauri's `test` feature supplies a *mocked* runtime: it dispatches
 * commands but never runs a WebView, so a green test there would say nothing
 * about whether a hostile label executes script in a browser. The two clauses
 * of UAT-019 that are still open are exactly the ones that need a real
 * engine, so the probe uses one — the same WebKit the console itself loads.
 *
 * What it drives is the *shipped* front-end. `ui/index.html` and `ui/app.js`
 * are read from disk and served with a base URI pointing at `ui/`, so their
 * relative `app.js` and `app.css` resolve and run as written. Only the
 * transport underneath is replaced, by `tests/probe-shim.js`, which answers
 * `invoke` with a hostile label. A hand-written copy of the render path would
 * have been easier and worthless: it would keep passing after app.js stopped
 * using textContent.
 *
 * The two things it decides, and how:
 *
 *   script execution  `window.__asv_pwned` is left `undefined` by the payload.
 *                     Read it back through `evaluate_javascript` and written
 *                     into the document title, because reading a JSCValue
 *                     from C is a second API with a second set of ways to get
 *                     it wrong.
 *   DOM shape         the payload must appear as a text node, so the document
 *                     must contain zero `img`, `script` or `svg` elements.
 *                     Counting them is stronger than reading the label back:
 *                     an escaped label can *look* right in a textContent
 *                     read while still having produced an element.
 *
 * And one more thing, because a passing test that cannot fail is not a test:
 * the same payload is also rendered through `innerHTML` in the same document.
 * If the probe cannot observe an execution there, it is not looking, and the
 * "clean" result on the real path means nothing.
 */

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>
#include <JavaScriptCore/JavaScript.h>

#include <stdio.h>
#include <string.h>

static const char *INSPECT_JS =
    "document.title = (window.__asv_pwned === undefined ? 'CLEAN' : 'PWNED')"
    " + '|elems=' + document.querySelectorAll('img,script,svg').length"
    " + '|textnode=' + (document.body.textContent.indexOf('onerror') !== -1)"
    " + '|buttons=' + document.querySelectorAll('button').length"
    " + '|cmds=' + (window.__asv_invocations || []).join(',');";

typedef struct {
    GtkWidget *window;
    WebKitWebView *view;
    gboolean expect_execution;
    int verdict;   /* 0 = did not run, 1 = passed, 2 = failed */
} Probe;

static void fail(Probe *p, const char *why) {
    g_printerr("PROBE FAIL: %s\n", why);
    p->verdict = 2;
    gtk_main_quit();
}

/* The verdict is the script's return value, read out of the JSCValue.
 *
 * Two earlier shapes of this were wrong in instructive ways. Writing the
 * verdict into `document.title` and reading `webkit_web_view_get_title()`
 * straight after is a race — the change has to travel back through the title
 * signal, and the run reported "the page never finished loading" for a page
 * that had finished. Passing the script to `run_javascript` as if it were
 * synchronous does not compile: in WebKitGTK 4.1 it takes a callback, like
 * every other call that touches the DOM. So the value comes back through
 * `evaluate_javascript_finish`, and the JSCValue is converted to a string
 * here rather than being poked at.
 */
static void on_inspected(GObject *source, GAsyncResult *res, gpointer data) {
    Probe *p = data;
    GError *err = NULL;
    JSCValue *value =
        webkit_web_view_evaluate_javascript_finish(WEBKIT_WEB_VIEW(source), res, &err);
    if (!value) {
        fail(p, err ? err->message : "could not evaluate the inspection script");
        if (err) g_error_free(err);
        return;
    }
    /* `jsc_value_to_string` hands back a `char *` the caller owns. An
     * intermediate version assumed it returned a `JSCString` and read
     * `jsc_string_get_utf8_cstr` off it; the header says `char *`, and the
     * compiler was right. */
    char *report = jsc_value_to_string(value);
    g_print("report=%s\n", report ? report : "(null)");
    if (!report) {
        fail(p, "the inspection script produced no string");
        return;
    }

    /* Vacuity guard.
     *
     * The first working run of this probe reported `CLEAN` and it meant
     * nothing: the shim had not loaded, so `app.js` threw on
     * `window.__TAURI__.core`, `refresh()` never ran, and no label was ever
     * rendered. There was no payload on the page to execute. The probe would
     * have passed a front-end that was completely broken.
     *
     * So CLEAN is only accepted if the page demonstrably did the work: the
     * command was invoked, the hostile text is in the DOM, and the document
     * holds the two script tags the page legitimately has. A page that
     * rendered nothing is a failure, not a pass. */
    if (!p->expect_execution) {
        if (strstr(report, "list_credentials") == NULL) {
            fail(p, "the front-end never invoked list_credentials, so nothing "
                    "was rendered and CLEAN is vacuous");
            return;
        }
        if (strstr(report, "textnode=true") == NULL) {
            fail(p, "the hostile label is not in the DOM, so the render path "
                    "under test never ran");
            return;
        }
        /* UAT-020, in the surface rather than in the policy.
         *
         * Exactly one button, for the `human_only` credential. The
         * `non_exportable` one must have none — not a disabled button, no
         * button — and the page carries both rows, so a count of one is a
         * statement about the difference between them rather than about a
         * console that renders nothing.
         *
         * This assertion is not decoration. It caught a real defect: the
         * front-end compared `exportability` against `"HumanOnly"` while
         * serde renames the variant to `human_only`, so neither branch
         * matched, no button was built, and a HumanOnly credential was
         * rendered identically to a NonExportable one. */
        if (strstr(report, "buttons=1") == NULL) {
            fail(p, "expected exactly one action button — the reveal for the "
                    "human_only credential and nothing for the non_exportable "
                    "one. UAT-020 is about the buttons not existing, not "
                    "about being disabled.");
            return;
        }
    }

    gboolean pwned = g_str_has_prefix(report, "PWNED");
    if (p->expect_execution && !pwned) {
        fail(p, "control: the innerHTML control did NOT execute, so this probe "
                "cannot observe execution and any CLEAN it reports is a false "
                "negative");
        return;
    }
    if (!p->expect_execution && pwned) {
        fail(p, "the shipped render path executed the payload");
        return;
    }
    g_free(report);
    p->verdict = 1;
    gtk_main_quit();
}

static void on_load_changed(WebKitWebView *view, WebKitLoadEvent event, gpointer data) {
    Probe *p = data;
    /* The signal fires for every transition — committed, started, finished.
     * Only the last means the document is parsed and its inline handlers have
     * had their chance. Inspecting on `committed` reports CLEAN before the
     * payload has been parsed at all. */
    if (event != WEBKIT_LOAD_FINISHED) return;
    webkit_web_view_evaluate_javascript(
        view, INSPECT_JS, -1, NULL, "uat-019-probe", NULL, on_inspected, p);
}

static char *slurp(const char *path) {
    gchar *contents = NULL;
    if (!g_file_get_contents(path, &contents, NULL, NULL)) return NULL;
    return contents;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        g_printerr("usage: %s <ui-dir> <control:0|1>\n", argv[0]);
        return 2;
    }
    gboolean control = argv[2][0] == '1';
    char *ui_dir = argv[1];

    char *index_path = g_build_filename(ui_dir, "index.html", NULL);
    char *shim_path = g_build_filename(ui_dir, "../tests/probe-shim.js", NULL);
    char *html = slurp(index_path);
    char *shim = slurp(shim_path);
    if (!html || !shim) {
        g_printerr("PROBE FAIL: could not read %s or %s\n", index_path, shim_path);
        return 2;
    }

    /* Stage the page and the shim in one directory.
     *
     * The shim was originally referenced as `../tests/probe-shim.js`, which
     * under a `file://` base URI is a different directory — and the page's own
     * `script-src 'self'` correctly refused it. The symptom was silent: no
     * shim, no `window.__TAURI__`, `app.js` throws, nothing renders, and the
     * probe reports a clean bill of health. Copying both into one staging
     * directory keeps them same-origin, so the CSP under test is the CSP that
     * was written rather than one loosened for the harness. */
    char *stage = g_dir_make_tmp("asv-uat019-XXXXXX", NULL);
    if (!stage) { g_printerr("PROBE FAIL: no staging dir\n"); return 2; }
    char *stage_index = g_build_filename(stage, "index.html", NULL);
    char *stage_shim = g_build_filename(stage, "probe-shim.js", NULL);
    g_file_set_contents(stage_shim, shim, -1, NULL);
    for (int i = 0; i < 3; i++) {
        const char *names[] = {"app.js", "app.css", NULL};
        if (!names[i]) break;
        char *src = g_build_filename(ui_dir, names[i], NULL);
        char *dst = g_build_filename(stage, names[i], NULL);
        char *content = slurp(src);
        if (content) g_file_set_contents(dst, content, -1, NULL);
        g_free(content); g_free(src); g_free(dst);
    }

    gtk_init(&argc, &argv);

    GtkWidget *win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(win), 800, 600);
    WebKitWebView *view = WEBKIT_WEB_VIEW(webkit_web_view_new());
    gtk_container_add(GTK_CONTAINER(win), GTK_WIDGET(view));
    gtk_widget_show_all(win);

    /* The shim goes in *before* the shipped app.js, and as a separate local
     * file rather than inline, so the page's own CSP (`script-src 'self'`)
     * still applies unchanged. If the shim needed `'unsafe-inline'` to load,
     * the CSP under test would have been weakened by the test. */
    char *tag = g_strdup_printf("<script src=\"probe-shim.js\"></script>");
    char *marker = strstr(html, "<script src=\"app.js\">");
    char *merged = NULL;
    if (marker) {
        GString *b = g_string_new("");
        g_string_append_len(b, html, marker - html);
        g_string_append(b, tag);
        g_string_append(b, marker);
        merged = g_string_free(b, FALSE);
    } else {
        merged = g_strdup(html);
    }

    if (control) {
        /* The control: the identical payload, delivered as markup. It must
         * execute. If it does not, every "CLEAN" this probe reports on the
         * real path is a false negative. */
        char *ctrl = g_strdup_printf(
            "<!DOCTYPE html><html><head><title>probe</title></head><body>"
            "<div id=\"t\"></div><script>"
            "document.getElementById('t').innerHTML = "
            "'<img src=x onerror=\"window.__asv_pwned=1\">';"
            "</" "script></body></html>");
        Probe p = { win, view, TRUE, 0 };
        g_signal_connect(view, "load-changed", G_CALLBACK(on_load_changed), &p);
        webkit_web_view_load_html(view, ctrl, NULL);
        gtk_main();
        g_free(ctrl);
        g_print("verdict=%d\n", p.verdict);
        return p.verdict == 1 ? 0 : 1;
    }

    Probe p = { win, view, FALSE, 0 };
    g_signal_connect(view, "load-changed", G_CALLBACK(on_load_changed), &p);
    g_printerr("merged-has-shim=%d\n", strstr(merged, "probe-shim.js") != NULL);
    /* Load the file by URI rather than by string.
     *
     * `load_html` synthesises a document whose origin is opaque, so the
     * page's own `script-src 'self'` refuses both of its local scripts. The
     * tags are still in the DOM — two `script` elements, which is exactly what
     * `elems=2` reported — and nothing executes, so the probe was watching an
     * inert document and calling it clean.
     *
     * The CSP is not wrong; it is stricter about a synthetic document than
     * about a real one. In the shipped app the page is served from Tauri's
     * custom protocol, where `'self'` matches and the scripts load. So the
     * harness has to give the document a real origin, and the honest way is
     * to load the file off disk rather than weaken the policy under test. */
    g_file_set_contents(stage_index, merged, -1, NULL);
    char *file_url = g_filename_to_uri(stage_index, NULL, NULL);
    char *base = g_path_get_dirname(file_url);
    webkit_web_view_load_uri(view, file_url);

    gtk_main();
    g_print("verdict=%d\n", p.verdict);

    g_free(base);
    g_free(merged);
    g_free(tag);
    g_free(html);
    g_free(shim);
    g_free(index_path);
    g_free(shim_path);
    return p.verdict == 1 ? 0 : 1;
}
