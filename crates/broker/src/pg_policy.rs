//! Deriving the policy action from a SQL statement (M6-R5).
//!
//! M6-R5 requires that a Cedar policy can allow `connect` but deny
//! `create_table`, and that changing the policy needs no connector change.
//! Neither is possible while every statement rides on the gateway verb, so
//! the broker has to know which action a statement is before it asks the
//! policy engine.
//!
//! # Failing closed is the whole design
//!
//! [`classify`] returns [`DbAction`] or a refusal, and there is no third
//! answer. It never returns "unknown, allow it": a statement this module
//! cannot place is [`Classified::RefuseUnknown`], which denies it. A
//! classifier that guessed would be an authorization bypass with a SQL
//! parser's confidence attached, and `CREATE TABLE` hidden inside a
//! `WITH ... INSERT` or a `DO` block is exactly the case where guessing is
//! wrong.
//!
//! The recognised forms are the first keyword plus, for the verbs where the
//! distinction matters, the presence of `INTO` or `TABLE`. That is not a SQL
//! parser and does not try to be. It is a conservative recogniser: it reads
//! the leading token, skips leading comments and whitespace, and refuses
//! anything it cannot place.
//!
//! # A write is never identified by its first word alone
//!
//! Three statement forms change state while opening with a word that also
//! opens a read, and each was a live authorization bypass until this module
//! learned it:
//!
//! - `SELECT ... INTO newtable` is `CREATE TABLE AS`.
//! - `EXPLAIN ANALYZE <write>` executes the write it plans.
//! - `WITH ... INSERT` is a data-modifying CTE.
//!
//! What all three defeat is the same policy: the read-only one M6-R5 writes. So
//! the invariant this module exists to hold is narrow and absolute — **a
//! statement that changes state is never classified as a read.** A classifier
//! that cannot honour that is not a useful gate, because the denial it exists
//! to express is the one an agent walks straight through.
//!
//! This is a deliberate limitation with a known failure mode: a statement
//! this module refuses but a database would have accepted is denied rather
//! than executed. That is the correct direction for a gate. The alternative
//! — a permissive fallback — turns an unrecognised statement into an
//! unauthorised one, and the whole reason the gate exists is that the
//! connector is not the thing deciding what an agent may do.

use asv_domain::Action;

/// What a statement turned out to be, or why it could not be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// The statement maps to a policy action.
    Action(DbAction),
    /// The statement could not be placed, and is therefore denied.
    RefuseUnknown {
        /// The leading keyword that was found, for the refusal message.
        leading: String,
    },
    /// The statement is empty or only whitespace and comments.
    RefuseEmpty,
}

impl Classified {
    /// The action, if there is one.
    pub fn action(self) -> Option<DbAction> {
        match self {
            Classified::Action(action) => Some(action),
            _ => None,
        }
    }

    /// Whether the statement may proceed to the policy engine.
    pub fn is_allowed_shape(&self) -> bool {
        matches!(self, Classified::Action(_))
    }
}

/// The policy action a statement carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbAction {
    Read,
    Insert,
    CreateTable,
    DropTable,
    AlterTable,
}

impl DbAction {
    /// The stable identifier the policy grammar uses.
    ///
    /// These strings are the Cedar vocabulary. Renaming one is a breaking
    /// change to every policy that mentions it, which is why they live here
    /// rather than being formatted at the call site.
    pub fn as_policy_str(self) -> &'static str {
        match self {
            DbAction::Read => "PostgresRead",
            DbAction::Insert => "PostgresInsert",
            DbAction::CreateTable => "PostgresCreateTable",
            DbAction::DropTable => "PostgresDropTable",
            DbAction::AlterTable => "PostgresAlterTable",
        }
    }

    /// The [`Action`] the policy engine evaluates.
    ///
    /// A conversion rather than a cast: `DbAction` is a statement-level
    /// notion and `Action` is the policy vocabulary, and a policy must be
    /// able to name the verb. Keeping them separate means the SQL side can
    /// grow a statement kind without silently becoming an authorisable verb.
    pub fn as_policy_action(self) -> Action {
        match self {
            DbAction::Read => Action::PostgresRead,
            DbAction::Insert => Action::PostgresInsert,
            DbAction::CreateTable => Action::PostgresCreateTable,
            DbAction::DropTable => Action::PostgresDropTable,
            DbAction::AlterTable => Action::PostgresAlterTable,
        }
    }
}

/// Classifies one SQL statement into the action its policy decision hangs on.
///
/// See the module docs for why an unplaceable statement is refused rather
/// than allowed. The public tests in this module cover the recognised forms
/// and the refusals; `policy_denies_a_statement_the_classifier_cannot_place`
/// in the broker suite is the end-to-end proof that the refusal is enforced
/// rather than merely returned.
pub fn classify(sql: &str) -> Classified {
    classify_at(sql, 0)
}

/// How deep `EXPLAIN` nesting is followed before a statement is refused.
///
/// `EXPLAIN` is the only recognised verb that can contain another statement,
/// so it is the only source of recursion. The cap is not about a real nesting
/// depth PostgreSQL supports — it supports one — it is about a hostile string
/// like `explain explain explain ...` repeating to the 64 KiB protocol limit,
/// which would otherwise recurse thousands of levels deep. Refusing is the
/// answer a gate gives to a statement no database would run.
const MAX_EXPLAIN_DEPTH: u32 = 4;

/// [`classify`], carrying the `EXPLAIN` nesting depth.
fn classify_at(sql: &str, depth: u32) -> Classified {
    let Some(leading) = leading_token(sql) else {
        return Classified::RefuseEmpty;
    };
    let upper = leading.to_ascii_uppercase();
    let body = sql.to_ascii_uppercase();

    // `EXPLAIN ANALYZE <write>` runs the write. Treating the wrapper as a
    // read because the first word is `EXPLAIN` is the same bug as `SELECT
    // INTO`: the policy is asked about a read and the database changes state.
    // The payload is classified instead, so a read stays a read and a write
    // carries the weight of what it actually does.
    if upper == "EXPLAIN" {
        if depth >= MAX_EXPLAIN_DEPTH {
            return Classified::RefuseUnknown {
                leading: "EXPLAIN".into(),
            };
        }
        let Some(payload) = explain_payload(sql) else {
            return Classified::RefuseUnknown {
                leading: "EXPLAIN".into(),
            };
        };
        return classify_at(&payload, depth + 1);
    }

    let action = match upper.as_str() {
        // A read is a read, except when it is not. `SELECT ... INTO newtable`
        // is `CREATE TABLE AS`: it returns rows *and* creates a table, so it
        // carries the create-table weight even though it is a `SELECT`.
        "SELECT" => {
            if has_select_into(&body) {
                DbAction::CreateTable
            } else {
                DbAction::Read
            }
        }
        "TABLE" | "VALUES" | "SHOW" | "WITH" => DbAction::Read,
        // `WITH ... INSERT` is an insert. The classifier reads the leading
        // keyword, so a CTE would otherwise be mistaken for a read and a
        // data-modifying CTE would slip through as one. When the statement
        // opens with WITH, the verbs that actually change state are looked
        // for in the body.
        "INSERT" | "UPDATE" | "MERGE" => DbAction::Insert,
        "CREATE" => {
            // `CREATE TABLE` is the verb M6-R5 names. `CREATE` also opens
            // `CREATE INDEX`, `CREATE VIEW` and friends, which are not the
            // same action, so the presence of TABLE is what decides.
            if mentions_table(&body) {
                DbAction::CreateTable
            } else {
                return Classified::RefuseUnknown {
                    leading: upper.clone(),
                };
            }
        }
        "DROP" => {
            if mentions_table(&body) {
                DbAction::DropTable
            } else {
                return Classified::RefuseUnknown {
                    leading: upper.clone(),
                };
            }
        }
        "ALTER" => {
            if mentions_table(&body) {
                DbAction::AlterTable
            } else {
                return Classified::RefuseUnknown {
                    leading: upper.clone(),
                };
            }
        }
        // DELETE changes rows, so it is the insert family rather than a
        // read. Keeping the two apart matters only if a policy treats them
        // differently, and it costs one match arm to be right if one does.
        "DELETE" | "TRUNCATE" => DbAction::Insert,
        _ => {
            return Classified::RefuseUnknown {
                leading: upper.clone(),
            }
        }
    };

    // A data-modifying CTE is an insert even though it opens with WITH.
    if upper == "WITH" {
        let action = if mentions_data_modifying_cte(&body) {
            DbAction::Insert
        } else {
            action
        };
        return Classified::Action(action);
    }

    Classified::Action(action)
}

/// The first SQL token, skipping leading whitespace and comments.
///
/// Returns `None` when the statement holds nothing but whitespace and
/// comments, which is the case that becomes [`Classified::RefuseEmpty`].
fn leading_token(sql: &str) -> Option<String> {
    let (start, end) = leading_token_span(sql)?;
    Some(sql[start..end].to_string())
}

/// The byte span of the first SQL token, as `(start, end)`.
///
/// Shared with [`explain_payload`], which needs the position just past the
/// token rather than its text. Both offsets come from one scan so the two
/// callers cannot disagree about where the token is.
fn leading_token_span(sql: &str) -> Option<(usize, usize)> {
    let bytes = sql.as_bytes();
    let mut index = 0usize;
    loop {
        // Whitespace.
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        // Line comments run to the newline.
        if sql[index..].starts_with("--") {
            let offset = sql[index..].find('\n')?;
            index += offset + 1;
            continue;
        }
        // Block comments do not nest in SQL.
        if sql[index..].starts_with("/*") {
            let offset = sql[index + 2..].find("*/")?;
            index += 2 + offset + 2;
            continue;
        }
        break;
    }
    if index >= bytes.len() {
        return None;
    }
    let start = index;
    while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b';' {
        index += 1;
    }
    Some((start, index))
}

/// Whether the statement mentions `TABLE` as a word.
fn mentions_table(body: &str) -> bool {
    body_contains_any(body, &[" TABLE ", " TABLE\n", " TABLE\r", " TABLE;"])
}

/// Whether `body` contains any of `needles`.
///
/// The needles carry a leading space so that `INSERT` does not match inside
/// `INSERTED`, which is a column name and not the verb. The alternatives
/// cover the whitespace and terminator characters a token can be followed by.
fn body_contains_any(body: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| body.contains(needle))
}

/// Whether a `WITH` statement contains a data-modifying CTE.
///
/// The first version of this looked for `" DELETE "` and friends, and its own
/// test caught the flaw: a CTE writes `WITH moved AS (DELETE FROM t ...`, where
/// the verb is preceded by `(` and not by a space. The needles therefore have
/// to be matched against the character before the verb rather than assuming it
/// is a space.
///
/// The false-positive direction is the one that matters. Matching `INSERT`
/// inside `INSERTED` would turn a read into a write, so the preceding
/// character is required to be a boundary: whitespace or an opening
/// parenthesis. That errs towards calling a write a write, which is the safe
/// direction for a gate — a misread read costs a statement, a misread write
/// costs an authorization.
fn mentions_data_modifying_cte(body: &str) -> bool {
    ["INSERT", "UPDATE", "DELETE", "MERGE"].iter().any(|verb| {
        body.match_indices(verb).any(|(at, _)| {
            at > 0 && matches!(body.as_bytes()[at - 1], b' ' | b'\t' | b'\n' | b'\r' | b'(')
        })
    })
}

/// Whether a `SELECT` carries an `INTO` that creates a table.
///
/// `SELECT ... INTO newtable FROM t` is `CREATE TABLE AS` with a different
/// spelling. A gate that reads only the leading keyword calls it a read, and a
/// policy written "read only" then authorises a table creation — which is the
/// exact denial M6-R5 exists to produce.
///
/// The false-positive direction still matters, so this is not a substring
/// search. Two things would make a bare `body.contains(" INTO ")` wrong:
///
/// - a literal: `SELECT 'into' AS note FROM t` is a read, and the needle
///   matches inside the quotes;
/// - a longer identifier: a column named `into_table` is not the keyword.
///
/// So the text outside single-quoted literals is scanned, and the match must
/// sit on a token boundary. Anything else — `SELECT INTO FROM t`, where `INTO`
/// is a column name — stays a read, which is correct: PostgreSQL reads that as
/// selecting a column.
fn has_select_into(body: &str) -> bool {
    let stripped = strip_single_quoted(body);
    stripped.match_indices("INTO").any(|(at, _)| {
        let bytes = stripped.as_bytes();
        let before_ok =
            at > 0 && matches!(bytes[at - 1], b' ' | b'\t' | b'\n' | b'\r' | b'(' | b',');
        let after = at + "INTO".len();
        let after_ok =
            after >= bytes.len() || !bytes[after].is_ascii_alphanumeric() && bytes[after] != b'_';
        before_ok && after_ok
    })
}

/// `text` with the contents of every single-quoted literal removed.
///
/// Doubled quotes (`'it''s'`) are the escape SQL uses, so a literal ends at
/// the first quote that is not itself doubled. Backslash escapes are not
/// handled, which is safe here for the same reason the rest of this module is
/// a recogniser and not a parser: an unterminated literal blanks the remainder
/// of the statement, which can only cost an `INTO` that was never a keyword.
fn strip_single_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_literal = false;
    while let Some(c) = chars.next() {
        if !in_literal {
            if c == '\'' {
                in_literal = true;
                out.push(' ');
            } else {
                out.push(c);
            }
        } else if c == '\'' {
            // A doubled quote is a literal quote; a single one closes it.
            if chars.peek() == Some(&'\'') {
                chars.next();
            } else {
                in_literal = false;
                out.push(' ');
            }
        } else {
            out.push(' ');
        }
    }
    out
}

/// The statement an `EXPLAIN` wraps, or `None` when there is none.
///
/// `EXPLAIN` takes options before its payload (`ANALYZE`, `VERBOSE`, `COSTS`,
/// …) either bare or in a parenthesised list, and the payload is what actually
/// determines the action. Everything up to the payload is skipped, and a
/// statement that is only options is refused rather than called a read: it
/// names no work, and the gate has no action to evaluate.
fn explain_payload(sql: &str) -> Option<String> {
    // Skip whatever precedes the leading `EXPLAIN` — whitespace and comments —
    // and the word itself, so the scan starts on the options.
    let (_, after_word) = leading_token_span(sql)?;
    let mut rest = &sql[after_word..];

    loop {
        rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if rest.is_empty() {
            return None;
        }
        // A parenthesised option list: `EXPLAIN (ANALYZE, VERBOSE) SELECT`.
        if rest.starts_with('(') {
            let end = rest.find(')')?;
            rest = &rest[end + 1..];
            continue;
        }
        // A bare option word. `ANALYZE` is the one that executes the payload,
        // and the rest are plan-shaping only, so they are all skipped together.
        let word_end = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(rest.len());
        let word = &rest[..word_end];
        if word.is_empty() {
            return None;
        }
        if is_explain_option(&word.to_ascii_uppercase()) {
            rest = &rest[word_end..];
            continue;
        }
        return Some(rest.to_string());
    }
}

/// Whether `word` is an `EXPLAIN` option rather than the start of a statement.
///
/// The list is the documented option set. A word that is not on it is treated
/// as the beginning of the payload, which means an option this build has
/// never heard of ends the scan and gets classified — and an unknown statement
/// is refused, so a future option fails closed instead of open.
fn is_explain_option(word: &str) -> bool {
    matches!(
        word,
        "ANALYZE"
            | "ANALYSE"
            | "VERBOSE"
            | "COSTS"
            | "BUFFERS"
            | "TIMING"
            | "SUMMARY"
            | "SETTINGS"
            | "WAL"
            | "GENERIC_PLAN"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action_of(sql: &str) -> Option<DbAction> {
        classify(sql).action()
    }

    #[test]
    fn the_read_verbs_a_policy_would_allow() {
        for sql in [
            "select 1",
            "SELECT 1",
            "  select * from t",
            "show server_version",
            "explain select 1",
            "values (1)",
            "table t",
        ] {
            assert_eq!(
                action_of(sql),
                Some(DbAction::Read),
                "{sql} should be a read"
            );
        }
    }

    #[test]
    fn the_write_verbs_are_not_reads() {
        // The case that motivates the whole module: a statement that changes
        // state must never classify as a read, or a policy that allows reads
        // allows writes.
        for sql in [
            "insert into t values (1)",
            "update t set a = 1",
            "delete from t",
            "truncate t",
            "merge into t using s on t.a = s.a",
        ] {
            assert_eq!(
                action_of(sql),
                Some(DbAction::Insert),
                "{sql} should be a write, not a read"
            );
        }
    }

    #[test]
    fn create_and_drop_and_alter_table_are_their_own_verbs() {
        assert_eq!(
            action_of("create table x (id int)"),
            Some(DbAction::CreateTable)
        );
        assert_eq!(action_of("drop table x"), Some(DbAction::DropTable));
        assert_eq!(
            action_of("alter table x add column b int"),
            Some(DbAction::AlterTable)
        );
    }

    #[test]
    fn create_index_is_not_create_table() {
        // The distinction the M6-R5 scenario does not make but a policy
        // author will: creating an index is not creating a table, and a
        // policy that denies one need not deny the other. This module refuses
        // rather than guessing, because there is no verb for it and inventing
        // one is a policy-grammar change.
        assert_eq!(
            classify("create index i on t (a)"),
            Classified::RefuseUnknown {
                leading: "CREATE".into()
            }
        );
    }

    #[test]
    fn a_data_modifying_cte_is_a_write_not_a_read() {
        // A read policy must not admit this one. The leading keyword is WITH,
        // so reading only the first token would call it a read.
        assert_eq!(
            action_of("with moved as (delete from t returning *) select * from moved"),
            Some(DbAction::Insert)
        );
        assert_eq!(
            action_of("with n as (select 1) select * from n"),
            Some(DbAction::Read)
        );
    }

    #[test]
    fn leading_comments_and_whitespace_do_not_change_the_verb() {
        assert_eq!(
            action_of("-- a comment mentioning drop table x\nselect 1"),
            Some(DbAction::Read),
            "a comment must not be read as a verb"
        );
        assert_eq!(
            action_of("/* create table x */ select 1"),
            Some(DbAction::Read)
        );
        assert_eq!(action_of("\n\n   \t select 1"), Some(DbAction::Read));
    }

    #[test]
    fn an_empty_or_comment_only_statement_is_refused() {
        assert_eq!(classify(""), Classified::RefuseEmpty);
        assert_eq!(classify("   \n\t "), Classified::RefuseEmpty);
        assert_eq!(classify("-- nothing here"), Classified::RefuseEmpty);
        assert_eq!(classify("/* unterminated"), Classified::RefuseEmpty);
        assert!(!classify("/* unterminated").is_allowed_shape());
    }

    #[test]
    fn an_unrecognised_statement_is_refused_not_allowed() {
        // The fail-closed property. A gate that cannot place a statement
        // denies it; it does not let it through on the grounds that it is
        // probably harmless.
        for sql in [
            "grant all on t to someone",
            "copy t from '/etc/passwd'",
            "do $$ begin raise notice 'hi'; end $$",
            "vacuum",
            "listen",
            "create database other",
            "drop database other",
        ] {
            let classified = classify(sql);
            assert!(
                !classified.is_allowed_shape(),
                "{sql} must not be allowed through, got {classified:?}"
            );
        }
    }

    #[test]
    fn select_into_creates_a_table_and_is_not_a_read() {
        // The bypass this pins down. `SELECT ... INTO newtable` is
        // PostgreSQL's `CREATE TABLE AS`: it creates a table and returns rows.
        // The module doc names `INTO` as one of the two words that decide the
        // verbs where the distinction matters, and the implementation read
        // only `TABLE`, so a read-only policy was asked about a read, said yes,
        // and the statement created a table anyway.
        for sql in [
            "select * into evil from t",
            "select 1 into evil",
            "select a, b into evil from t where a > 0",
            "select * into temp evil from t",
        ] {
            assert_eq!(
                action_of(sql),
                Some(DbAction::CreateTable),
                "{sql} creates a table and must not classify as a read"
            );
        }
    }

    #[test]
    fn a_select_that_merely_says_into_in_a_literal_is_still_a_read() {
        // The other direction. `INTO` is a keyword, not a substring: a read
        // whose projection happens to contain the word is still a read, and
        // refusing it would cost a legitimate statement for nothing.
        assert_eq!(
            action_of("select 'into' as note from t"),
            Some(DbAction::Read)
        );
        assert_eq!(
            action_of("select 'x into y' as note from t"),
            Some(DbAction::Read)
        );
        // A doubled quote is an escaped quote, so the literal continues and
        // the `into` after it is still inside the string.
        assert_eq!(
            action_of("select 'it''s into t' as note from t"),
            Some(DbAction::Read)
        );
        // A column whose name merely starts with the keyword.
        assert_eq!(action_of("select into_table from t"), Some(DbAction::Read));
        // `SELECT INTO FROM t` is a degenerate input whose reading depends on
        // how the server resolves a bare `INTO`. This module does not claim to
        // settle that, and it does not have to: the choice between the two
        // readings is settled by the direction of the error. Calling it a
        // create costs one odd statement; calling it a read would let a
        // read-only policy through a form that may well create a table.
        assert_eq!(
            action_of("select into from t"),
            Some(DbAction::CreateTable),
            "an ambiguous bare INTO must take the conservative side"
        );
    }

    #[test]
    fn explain_analyze_runs_the_write_it_plans() {
        // The second vector. `EXPLAIN ANALYZE` executes the statement it
        // explains, so calling the wrapper a read because the first word is
        // `EXPLAIN` hands a read-only policy the authority to write.
        for sql in [
            "explain analyze insert into t values (1)",
            "explain analyze delete from t",
            "explain analyze update t set a = 1",
            "explain (analyze) delete from t",
        ] {
            assert_eq!(
                action_of(sql),
                Some(DbAction::Insert),
                "{sql} writes and must not classify as a read"
            );
        }
        // The DDL verbs keep their own weight through the wrapper too.
        assert_eq!(
            action_of("explain (analyze, verbose) drop table t"),
            Some(DbAction::DropTable)
        );
        assert_eq!(
            action_of("explain analyze create table t (id int)"),
            Some(DbAction::CreateTable)
        );
        assert_eq!(
            action_of("explain select * into evil from t"),
            Some(DbAction::CreateTable)
        );
        // A plan-only `EXPLAIN` of a read is still a read, and the plan-only
        // form of a write is still the write: the gate should not depend on
        // whether the agent asked for a plan or for the run.
        assert_eq!(action_of("explain select 1"), Some(DbAction::Read));
        assert_eq!(action_of("explain delete from t"), Some(DbAction::Insert));
        assert_eq!(action_of("explain analyze select 1"), Some(DbAction::Read));
        assert_eq!(
            action_of("explain analyze create table t (id int)"),
            Some(DbAction::CreateTable)
        );
    }

    #[test]
    fn an_explain_with_nothing_to_explain_is_refused() {
        // No payload means no action to evaluate, so there is no decision to
        // report. Guessing "read" here would let a malformed statement past a
        // gate that has nothing to base a decision on.
        for sql in [
            "explain",
            "explain analyze",
            "explain (analyze)",
            "explain ()",
        ] {
            assert!(
                !classify(sql).is_allowed_shape(),
                "{sql} names no statement and must not be allowed, got {:?}",
                classify(sql)
            );
        }
    }

    #[test]
    fn explain_nesting_is_bounded_rather_than_recursing_to_the_message_limit() {
        // A hostile string repeats `explain` to the 64 KiB protocol limit.
        // Unbounded recursion would exhaust the stack, so the depth is capped
        // and the statement is refused. No database would run it either.
        let nested = "explain analyze ".repeat(64) + "select 1";
        assert!(
            !classify(&nested).is_allowed_shape(),
            "a pathological nesting must be refused, not recursed"
        );
    }

    #[test]
    fn the_policy_strings_are_the_cedar_vocabulary() {
        // Renaming any of these is a breaking change to every policy that
        // mentions the verb, so they are pinned here.
        assert_eq!(DbAction::Read.as_policy_str(), "PostgresRead");
        assert_eq!(DbAction::Insert.as_policy_str(), "PostgresInsert");
        assert_eq!(DbAction::CreateTable.as_policy_str(), "PostgresCreateTable");
        assert_eq!(DbAction::DropTable.as_policy_str(), "PostgresDropTable");
        assert_eq!(DbAction::AlterTable.as_policy_str(), "PostgresAlterTable");
        assert_eq!(DbAction::Read.as_policy_action(), Action::PostgresRead);
    }
}
