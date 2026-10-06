//! Rows for the curl family, kept beside the code that has to survive them.
//!
//! Two of these exist because the parser has a specific rule that a
//! less-careful implementation gets wrong in a way that looks correct:
//! `user = "x"` has a space **and** an `=`, and stopping at the space leaves
//! `= "x"` as the value. Every downstream number is then a measurement of a
//! character the file does not contain, which is the same class of defect the
//! Gradle rows found in its own unescaper.

use super::*;

fn parse(text: &str) -> Vec<ParsedOption> {
    parse_curlrc(text).expect("the fixture is well formed")
}

fn names(text: &str) -> Vec<String> {
    parse(text).into_iter().map(|o| o.name).collect()
}

fn value_of(text: &str, name: &str) -> Option<String> {
    parse(text)
        .into_iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value)
}

// ---------------------------------------------------------------- separators

#[test]
fn a_bare_name_is_a_flag_and_carries_no_value() {
    let options = parse("silent\n");
    assert_eq!(options.len(), 1);
    assert_eq!(options[0].name, "silent");
    assert_eq!(options[0].value, None);
}

#[test]
fn whitespace_equals_and_colon_all_separate_an_option_from_its_value() {
    assert_eq!(
        value_of("user alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
    assert_eq!(
        value_of("user=alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
    assert_eq!(
        value_of("user:alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
    assert_eq!(
        value_of("user = alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
    assert_eq!(
        value_of("user  =  alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
}

/// **The row that would have caught the parser's worst bug.** `user = "x"` has
/// a space and an `=`; a parser that stops at the first whitespace keeps
/// `= "x"` and reports a length six bytes longer than the value in the file.
#[test]
fn a_separator_and_whitespace_around_it_are_all_consumed() {
    let raw = "user = \"alice:secret\"";
    assert_eq!(value_of(raw, "user").as_deref(), Some("alice:secret"));
    let (credentials, _) = classify(parse(raw));
    assert_eq!(credentials[0].user_len, 5);
    assert_eq!(credentials[0].password_len, 6);
}

/// curl's rule: with leading dashes, only whitespace separates. `--user=alice`
/// is not a spelling of anything, and reporting it as one inert option would
/// put a credential-looking line into the report as a flag.
#[test]
fn a_dashed_option_may_not_use_colon_or_equals_as_its_separator() {
    assert_eq!(
        parse_curlrc("--user=alice:secret\n").unwrap_err(),
        CurlParseError::DashedSeparator {
            name: "user=alice:secret".to_string()
        }
    );
    // Whitespace after dashes is the one form curl does accept.
    assert_eq!(
        value_of("--user alice:secret\n", "user").as_deref(),
        Some("alice:secret")
    );
}

// ------------------------------------------------------------- name spelling

/// Three spellings, one option. A report listing three rows for one credential
/// is counting spellings, not credentials.
#[test]
fn the_three_spellings_of_user_are_one_option() {
    assert_eq!(
        names("--user alice:s\n-u alice:s\nuser = alice:s\n"),
        ["user", "u", "user"]
    );
    let (credentials, _) = classify(parse("--user alice:s\n-u bob:t\n"));
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].option, "user");
    assert_eq!(credentials[1].option, "u");
}

/// curl compares option names case-insensitively, and a `.curlrc` written by
/// hand spells them any way.
#[test]
fn an_option_name_is_matched_case_insensitively() {
    let (credentials, _) = classify(parse("USER = alice:secret\n"));
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].kind, CurlCredential::User);
}

// ------------------------------------------------------------------ comments

/// "# in the first non-blank column", so leading whitespace does not turn a
/// comment into an option named `#`.
#[test]
fn a_hash_in_the_first_non_blank_column_comments_the_line_out() {
    assert_eq!(names("# user = alice:secret\n"), Vec::<String>::new());
    assert_eq!(names("   # user = alice:secret\n"), Vec::<String>::new());
    assert_eq!(names("\t#user=alice:secret\n"), Vec::<String>::new());
    assert_eq!(
        value_of("user = a:b\n# user = c:d\n", "user").as_deref(),
        Some("a:b")
    );
}

// --------------------------------------------------------------------- quotes

#[test]
fn a_quoted_value_keeps_the_whitespace_inside_it() {
    assert_eq!(
        value_of("user = \"al ice:se cret\"\n", "user").as_deref(),
        Some("al ice:se cret")
    );
}

#[test]
fn an_unterminated_quote_is_refused_rather_than_read_as_the_rest_of_the_file() {
    assert_eq!(
        parse_curlrc("user = \"alice:secret\nsilent\n").unwrap_err(),
        CurlParseError::UnterminatedQuote { number: 1 }
    );
}

#[test]
fn the_escape_table_is_curls_and_not_shells() {
    // Backslash-quote and backslash-backslash are the two that matter for a
    // credential with a quote or a Windows path in it.
    assert_eq!(unescape_value("\"a\\\"b\"", 1).unwrap(), "a\"b");
    assert_eq!(unescape_value("\"a\\\\b\"", 1).unwrap(), "a\\b");
    assert_eq!(unescape_value("\"a\\tb\"", 1).unwrap(), "a\tb");
    assert_eq!(unescape_value("\"a\\nb\"", 1).unwrap(), "a\nb");
    assert_eq!(unescape_value("\"a\\rb\"", 1).unwrap(), "a\rb");
    assert_eq!(unescape_value("\"a\\vb\"", 1).unwrap(), "a\u{0b}b");
}

/// **"A backslash preceding any other letter is ignored"** — the backslash goes
/// and the letter stays. This is the row that catches a shell reading, where
/// `\d` would survive intact and `C:\dir` would come back a byte short.
#[test]
fn a_backslash_before_any_other_letter_is_dropped_and_the_letter_kept() {
    assert_eq!(unescape_value("\"C:\\dir\"", 1).unwrap(), "C:dir");
    assert_eq!(unescape_value("\"\\q\"", 1).unwrap(), "q");
}

#[test]
fn an_unquoted_value_is_taken_literally() {
    assert_eq!(value_of("max-time 30\n", "max-time").as_deref(), Some("30"));
}

// ---------------------------------------------------------------- the compound

/// **The split is on the first colon**, which is what curl does. A password
/// containing a colon is legal; splitting on the last one turns the username
/// into `alice:extra` and reports a user nobody has.
#[test]
fn the_credential_splits_on_the_first_colon_not_the_last() {
    let (credentials, _) = classify(parse("user = \"alice:pass:with:colons\"\n"));
    assert_eq!(credentials[0].user_len, 5);
    assert_eq!(credentials[0].password_len, 16);
}

#[test]
fn a_user_with_no_colon_authenticates_with_an_empty_password() {
    let (credentials, _) = classify(parse("user = alice\n"));
    assert_eq!(credentials[0].user_len, 5);
    assert_eq!(credentials[0].has_password, false);
    assert_eq!(credentials[0].password_len, 0);
}

#[test]
fn a_password_with_no_username_is_still_a_password() {
    let (credentials, _) = classify(parse("user = \":secret\"\n"));
    assert_eq!(credentials[0].user_len, 0);
    assert_eq!(credentials[0].has_password, true);
    assert_eq!(credentials[0].password_len, 6);
}

#[test]
fn both_credential_options_are_named_and_nothing_else_is() {
    let (credentials, rest) = classify(parse("user = a:b\nproxy-user = c:d\nsilent\n"));
    assert_eq!(credentials.len(), 2);
    assert_eq!(credentials[0].kind, CurlCredential::User);
    assert_eq!(credentials[1].kind, CurlCredential::ProxyUser);
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].option, "silent");
    assert_eq!(rest[0].has_value, false);
}

/// **No env-reference column exists here, and this is why.** npm, Maven and
/// Gradle all expand `${VAR}`; curl does not, so a literal in a `.curlrc` is a
/// literal and the field would be false on every row of every real file.
#[test]
fn a_dollar_brace_in_a_curlrc_is_part_of_the_password_not_a_variable() {
    let (credentials, _) = classify(parse("user = \"alice:${HOME}\"\n"));
    assert_eq!(credentials[0].password_len, 7);
    assert_eq!(credentials[0].has_password, true);
}

// ------------------------------------------------------------------ ceilings

#[test]
fn a_line_count_past_the_ceiling_is_refused() {
    let text = "silent\n".repeat(MAX_CURLRC_LINES + 1);
    assert_eq!(
        parse_curlrc(&text).unwrap_err(),
        CurlParseError::TooManyLines {
            number: MAX_CURLRC_LINES + 1
        }
    );
}

#[test]
fn a_file_at_the_line_ceiling_is_still_read() {
    let text = "silent\n".repeat(MAX_CURLRC_LINES);
    assert_eq!(parse_curlrc(&text).unwrap().len(), MAX_CURLRC_LINES);
}

/// The depth ceiling exists as a documented absence, not as a number. A ceiling
/// that cannot be violated is not a safety property.
///
/// Measured on breadth and on a single very long line, because those are the two
/// shapes this format can actually be given. It is deliberately **not** measured
/// by repeating one option ten thousand times: that is depth in appearance only
/// and [`MAX_CURLRC_LINES`] refuses it, which would make this row a second name
/// for the line ceiling while claiming to be about something else.
#[test]
fn there_is_no_depth_limit_because_the_format_has_no_nesting() {
    let long_value = "a".repeat(200_000);
    let text = format!("user = \"alice:{long_value}\"\n");

    // Well past MAX_CURLRC_BYTES would be refused by the reader, so this stays
    // under it: the point is that the *parser* holds the whole line without
    // recursing, not that an enormous file is acceptable.
    assert!(text.len() < MAX_CURLRC_BYTES as usize);

    let (credentials, _) = classify(parse(&text));
    assert_eq!(credentials[0].user_len, 5);
    assert_eq!(credentials[0].password_len, long_value.len());
}

// -------------------------------------------------------------------- refusal

#[test]
fn a_line_that_is_only_dashes_has_no_option_name() {
    assert_eq!(
        parse_curlrc("--\n").unwrap_err(),
        CurlParseError::Malformed { number: 1 }
    );
}

#[test]
fn an_empty_file_parses_to_nothing_rather_than_failing() {
    assert_eq!(parse_curlrc(""), Ok(Vec::new()));
    assert_eq!(parse_curlrc("\n\n\n"), Ok(Vec::new()));
}
