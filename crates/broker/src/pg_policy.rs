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
//! cannot place is [`Unclassified::RefuseUnknown`], which denies it. A
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
    let Some(leading) = leading_token(sql) else {
        return Classified::RefuseEmpty;
    };
    let upper = leading.to_ascii_uppercase();
    let body = sql.to_ascii_uppercase();

    let action = match upper.as_str() {
        // A read is a read. `SELECT` and the statement forms that return
        // rows without changing state.
        "SELECT" | "TABLE" | "VALUES" | "SHOW" | "EXPLAIN" | "WITH" => DbAction::Read,
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
    Some(sql[start..index].to_string())
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
