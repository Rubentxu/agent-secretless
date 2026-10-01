//! Strings that came from outside become data, never markup.
//!
//! UAT-019's first clause: a hostile string in a credential label is
//! *"rendered as data"*, and there is *"no script execution"*.
//!
//! The second half of that is a Content-Security-Policy and lives in the
//! shell's configuration. This module is the first half, and it is here
//! because "rendered as data" is a property of what the rest of the program
//! can do with the string, not a property of the renderer.
//!
//! The mechanism is a type. [`Untrusted`] holds a string the program did not
//! author; [`SafeText`] is what the renderer may be given, and the only way
//! out of `SafeText` is [`SafeText::render`], which escapes. There is no
//! `From<SafeText> for String`, and no `Deref<Target = str>`, so a shell that
//! receives a `SafeText` cannot accidentally hand raw bytes to an HTML sink.
//!
//! What this cannot do, and does not pretend to: it cannot make a renderer
//! safe. A renderer that ignores its input's type and concatenates anyway is
//! still unsafe. The type raises the cost of the mistake; the CSP and the
//! review are what make it absent.

use core::fmt;

/// A string the program did not author.
///
/// Constructed from anything, including a literal. There is no safe way to
/// hold untrusted text except inside this type, which is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untrusted(String);

impl Untrusted {
    /// Wraps a string as untrusted.
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// Wraps a string literal as untrusted.
    ///
    /// Exists so tests can express the hostile input without a `String`
    /// dance. Using it in production is a smell: literals are authored.
    #[cfg(test)]
    pub fn literal(value: &str) -> Self {
        Self(String::from(value))
    }

    // Note the absence of any accessor returning the raw string. The first
    // version of this type had one, and it became dead the moment escaping
    // moved to construction: once `into_safe` escapes, nothing needs the
    // unescaped form, and an accessor that could return it would be a way for
    // a caller to get the dangerous version of a string out of the one type
    // that exists to prevent that.
}

/// Text that has been through [`Untrusted::into_safe`] and may be rendered.
///
/// It stores the **escaped** form, and that is the only form it has. The
/// first version of this type stored the raw string and escaped in `render()`,
/// which meant a method called `as_escaped()` returned unescaped text — a
/// method whose name was the opposite of what it did, on the one type whose
/// whole job is that they cannot differ. Escaping once, on the boundary, means
/// there is a single representation and no accessor that can return the other
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeText(String);

impl SafeText {
    fn escaped(value: String) -> Self {
        let mut out = String::with_capacity(value.len());
        for ch in value.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#x27;"),
                other => out.push(other),
            }
        }
        Self(out)
    }

    /// The text, escaped, ready for an HTML text context.
    ///
    /// "Rendered as data" means exactly this: a label that is literally
    /// `<script>` renders as the characters `&lt;script&gt;` and is not an
    /// element.
    pub fn render(&self) -> String {
        self.0.clone()
    }

    /// The escaped text, borrowed.
    ///
    /// Safe to serialise, interpolate, or log: it is the same bytes
    /// [`Self::render`] returns, because there is only one.
    pub fn as_escaped(&self) -> &str {
        &self.0
    }

    /// Whether the source text was empty or only whitespace.
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl Untrusted {
    /// Sanitises into renderable text.
    pub fn into_safe(self) -> SafeText {
        SafeText::escaped(self.0)
    }
}

impl fmt::Display for SafeText {
    /// Displays the **escaped** text.
    ///
    /// `Display` is what a logging call and a format string reach for, so
    /// making it the escaped form means the easiest way to print a label is
    /// also the safe one. Displaying the raw form would make this the
    /// easiest way to be unsafe.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe(value: &str) -> SafeText {
        Untrusted::new(value.to_string()).into_safe()
    }

    #[test]
    fn a_script_tag_renders_as_data() {
        // The UAT-019 case, stated as the input an operator could actually
        // type into a label field.
        let rendered = safe("<script>alert('x')</script>").render();
        assert_eq!(
            rendered,
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
        );
        assert!(
            !rendered.contains('<'),
            "a rendered label must contain no opening delimiter at all: {rendered}"
        );
        assert!(!rendered.contains('>'), "{rendered}");
    }

    #[test]
    fn an_attribute_breakout_renders_as_data() {
        // The other half: breaking out of an attribute to add a handler.
        // The dangerous character is the quote, not the `=` — the `=` is
        // inert once the quote that made it a *new* attribute is escaped.
        // The first version of this test asserted the absence of `=`, which
        // was over-strict and would have failed for a correct implementation.
        let rendered = safe("\" onmouseover=\"alert(1)").render();
        assert!(
            !rendered.contains('"'),
            "quotes must be escaped, or the attribute can be closed and reopened: {rendered}"
        );
        assert!(
            !rendered.contains('<') && !rendered.contains('>'),
            "no markup delimiter may survive: {rendered}"
        );
        assert_eq!(rendered, "&quot; onmouseover=&quot;alert(1)");
    }

    #[test]
    fn an_event_handler_url_renders_as_data() {
        for hostile in [
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "</textarea><script>alert(1)</script>",
            "\u{2028}<script>",
        ] {
            let rendered = safe(hostile).render();
            assert!(
                !rendered.contains('<') && !rendered.contains('>'),
                "hostile input {hostile:?} rendered with a delimiter: {rendered}"
            );
        }
    }

    #[test]
    fn ampersand_is_escaped_so_escaping_is_not_reversible() {
        // Without this, `&lt;` in a label would become indistinguishable from
        // a `<` that was escaped, and double-rendering would corrupt it.
        let rendered = safe("a & b < c").render();
        assert_eq!(rendered, "a &amp; b &lt; c");
    }

    #[test]
    fn display_gives_the_escaped_form_not_the_raw_one() {
        // The trap: `{}` in a log line is the most common way a label
        // reaches an output stream, so Display must not be the raw text.
        let label = safe("<b>x</b>");
        assert_eq!(format!("{label}"), "&lt;b&gt;x&lt;/b&gt;");
        assert!(!format!("{label}").contains('<'));
    }

    #[test]
    fn ordinary_text_survives_unchanged_in_meaning() {
        // Escaping everything would be safe and useless. Plain labels must
        // still read correctly.
        for plain in ["api token", "prod/db", "clave-de-la-casa", "clé 2026"] {
            assert_eq!(safe(plain).render(), plain);
        }
    }

    #[test]
    fn blank_detection_sees_through_escaping() {
        assert!(safe("   ").is_blank());
        assert!(safe("\t\n").is_blank());
        assert!(!safe(" x ").is_blank());
        // And a hostile input that renders to nothing visible is still not
        // blank in the source, which is the honest reading.
        assert!(!safe("<script>").is_blank());
    }

    #[test]
    fn the_escaped_form_is_also_reachable_as_a_field_for_serialisers() {
        // A shell that serialises a label into a payload needs the escaped
        // string, and needs it to be the escaped one.
        let label = safe("a<b");
        assert_eq!(label.as_escaped(), "a&lt;b");
    }
}
