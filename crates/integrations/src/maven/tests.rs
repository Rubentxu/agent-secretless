//! The Maven family's rows.
//!
//! Two of them carry the weight. [`the_serialised_report_contains_no_credential`]
//! asserts the property the crate exists to hold, against the *serialised* JSON
//! rather than against the struct — because a claim about the fields written
//! today is not a claim about what a caller receives, and what a caller receives
//! reaches a terminal, a log and an agent's context.
//!
//! [`an_artifactory_key_under_configuration_is_named_and_not_read`] is the other,
//! and it is the row this family forced. An adapter that modelled only
//! `<username>` and `<password>` would have printed a tidy report and silently
//! omitted a second credential sitting in a `<configuration>` block — which is
//! where Artifactory, Nexus and friends keep their API keys.
//!
//! Every row below names the mutation that turns it red. A row that cannot
//! answer that question is not evidence.

use super::*;

const PASSWORD: &str = "hunter2-not-a-real-secret";
const ARTIFACTORY_KEY: &str = "AKCp8REALLYWELLFAKEKEY0123";

/// A `settings.xml` with one literal credential, one env-referenced one, and
/// one with nothing in it at all.
///
/// The third is not padding: "no password" and "a password of length zero" are
/// different claims and only one of them is true.
fn settings() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <localRepository>/var/cache/m2</localRepository>
  <servers>
    <server>
      <id>acme-releases</id>
      <username>deploy-bot</username>
      <password>{PASSWORD}</password>
    </server>
    <server>
      <id>acme-from-env</id>
      <username>deploy-bot</username>
      <password>${{env.ACME_DEPLOY_TOKEN}}</password>
    </server>
    <server>
      <id>acme-anonymous</id>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>acme-internal</id>
      <url>https://repo.acme.test/maven</url>
      <mirrorOf>external:*,!acme-releases</mirrorOf>
    </mirror>
  </mirrors>
  <proxies>
    <proxy>
      <id>acme-proxy</id>
      <active>true</active>
      <protocol>https</protocol>
      <host>proxy.acme.test</host>
      <port>3128</port>
      <username>proxy-user</username>
      <password>proxy-password</password>
    </proxy>
  </proxies>
</settings>"#
    )
}

fn report(text: &str) -> MavenDiscovery {
    let parsed = parse_settings(text).expect("parses");
    MavenDiscovery {
        files: vec![MavenFile {
            origin: crate::Origin::User,
            fingerprint: fingerprint_for("/home/u/.m2/settings.xml"),
            local_repository: parsed.local_repository,
            servers: parsed.servers,
            mirrors: parsed.mirrors,
            proxies: parsed.proxies,
        }],
        findings: Vec::new(),
    }
}

fn fingerprint_for(path: &str) -> crate::fingerprint::FileFingerprint {
    crate::fingerprint::FileFingerprint {
        path: path.into(),
        resolved_path: path.into(),
        inode: 1,
        owner_uid: 1000,
        mode: 0o600,
        size: 0,
        digest: "sha256:0".into(),
    }
}

/// **The property this whole crate exists to hold, asserted against the
/// serialised report.**
///
/// A field added tomorrow, a derived `Debug`, a flattened nested struct — none
/// of them can leak through this assertion. A struct-shape assertion could be
/// satisfied by the types I happened to write and would say nothing about the
/// next edit.
///
/// *Red by:* `password_len: Option<usize>` becoming `password: Option<String>`,
/// or `credential_len` being handed the raw text instead of a count.
#[test]
fn the_serialised_report_contains_no_credential() {
    let discovery = report(&settings());
    // Asserted before serialising, in its own scope: `into_discovery` consumes
    // the value, and a row that re-read after the move would be measuring a
    // second object rather than the one it printed.
    {
        assert_eq!(discovery.files[0].servers.len(), 3);
        assert_eq!(discovery.files[0].servers[0].password_len, Some(25));
        assert_eq!(discovery.files[0].proxies[0].password_len, Some(14));
    }
    let json = serde_json::to_string(&discovery.into_discovery()).expect("serialises");
    assert!(
        !json.contains(PASSWORD),
        "the password reached the report: {json}"
    );
    assert!(
        !json.contains("proxy-password"),
        "the proxy password reached the report: {json}"
    );
}

/// `Debug` is a different code path from `Serialize`, and a report that is safe
/// in JSON routinely is not in a log line. They have gone their separate ways
/// before, so they are asserted separately.
///
/// *Red by:* deriving or hand-writing a `Debug` that formats the parsed text.
#[test]
fn the_debug_rendering_contains_no_credential_either() {
    let rendered = format!("{:?}", report(&settings()));
    assert!(
        !rendered.contains(PASSWORD),
        "the password reached Debug: {rendered}"
    );
    assert!(
        !rendered.contains("proxy-password"),
        "the proxy password reached Debug: {rendered}"
    );
}

/// **The row the second family forced into existence.**
///
/// `<server><configuration>` is where Artifactory and Nexus keep an API key.
/// An adapter that modelled only `<username>`/`<password>` would report one
/// credential and silently omit the other, and a report that says "here is the
/// credential" while a second one is invisible is worse than one that says
/// nothing at all.
///
/// The element is therefore *named* and its text *measured* — present and not
/// described, which is a different claim from absent.
///
/// *Red by:* dropping the `undescribed` collection (the row then fails on the
/// count), or reporting the `<value>` text instead of its length.
#[test]
fn an_artifactory_key_under_configuration_is_named_and_not_read() {
    let text = format!(
        r#"<settings>
  <servers>
    <server>
      <id>acme-releases</id>
      <username>deploy-bot</username>
      <password>{PASSWORD}</password>
      <configuration>
        <httpHeaders>
          <property>
            <name>X-JFrog-Art-Api</name>
            <value>{ARTIFACTORY_KEY}</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>"#
    );
    let discovery = report(&text);
    let server = &discovery.files[0].servers[0];

    // It is not dropped: an adapter that ignored it would report zero.
    assert_eq!(server.undescribed.len(), 1, "{server:?}");
    assert_eq!(server.undescribed[0].element, "configuration");
    // And it is measured across the whole subtree, not just a direct child —
    // a `<configuration>` holding one `<property>` has no direct text of its
    // own, and a first implementation that measured only that would report 0
    // and look like it had found nothing.
    assert!(
        server.undescribed[0].len > ARTIFACTORY_KEY.len(),
        "measured {} bytes, which cannot include the key",
        server.undescribed[0].len
    );

    let json = serde_json::to_string(&discovery.into_discovery()).expect("serialises");
    assert!(
        !json.contains(ARTIFACTORY_KEY),
        "the vendor API key reached the report: {json}"
    );
}

/// §5's first requirement: a DOCTYPE is refused **as such**, not as a parse
/// failure.
///
/// The distinction is the point — an operator reading "not well-formed XML"
/// would not know a document type declaration was attempted, and §5 asks for
/// that to be visible.
///
/// *Red by:* `allow_dtd: true`.
#[test]
fn a_document_with_a_dtd_is_refused_before_its_contents_are_read() {
    let text = r#"<!DOCTYPE settings [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<settings><servers><server><id>x</id></server></servers></settings>"#;
    let error = parse_settings(text).expect_err("a DTD must not be accepted");
    match &error {
        MavenError::DtdRefused { reason } => {
            assert!(reason.contains("DOCTYPE"), "{error}")
        }
        other => panic!("expected a DTD refusal, got {other:?}"),
    }
}

/// §5's second requirement, and the one with a body: an entity reference with
/// no DTD behind it.
///
/// This is the XXE shape that reaches a parser which *does* accept DTDs, so it
/// is asserted separately from the DOCTYPE row: a parser could refuse
/// declarations and still try to resolve a reference, and then this row is the
/// only one that notices.
///
/// *Red by:* mapping `UnknownEntityReference` to `Malformed`, which loses the
/// named entity.
#[test]
fn an_undeclared_entity_reference_is_refused_and_named() {
    let text = "<settings><servers><server><id>&xxe;</id></server></servers></settings>";
    let error = parse_settings(text).expect_err("an undeclared entity must not resolve");
    match &error {
        MavenError::DtdRefused { reason } => {
            // Named, so an operator can see *what* was attempted.
            assert!(reason.contains("xxe"), "the entity is not named: {error}");
        }
        other => panic!("expected an entity refusal, got {other:?}"),
    }
}

/// A real `settings.xml` carries `xsi:schemaLocation` pointing at an HTTPS URL,
/// and `roxmltree` parses it as an ordinary attribute.
///
/// If anything ever resolved that, every discovery on a real machine would
/// block on the network. So this row is not decorative: it is the regression
/// guard against a future "helpful" resolver. *Red by:* handing the parser a
/// resolver — the row times out or fails.
///
/// *Not* a claim that the crate cannot open a socket. It cannot, because
/// `roxmltree` declares no dependencies and is `#![forbid(unsafe_code)]`; that
/// is structural and belongs in the dependency review, not here.
#[test]
fn the_schema_location_is_parsed_as_text_and_never_fetched() {
    let text = r#"<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0
                              https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers><server><id>acme</id></server></servers>
</settings>"#;
    let parsed = parse_settings(text).expect("a namespaced document parses");
    assert_eq!(parsed.servers[0].id, "acme");
}

/// §5's fourth requirement: the ceiling, and it is refused by name.
///
/// *Red by:* deleting the `len > MAX_SETTINGS_BYTES` comparison — the file is
/// then read and parsed like any other, and the row fails on the variant.
#[test]
fn a_file_over_the_ceiling_is_refused_without_being_read() {
    let dir = tempfile::tempdir().expect("a scratch dir");
    let path = dir.path().join("settings.xml");
    std::fs::write(&path, "x".repeat((MAX_SETTINGS_BYTES + 1) as usize)).expect("writes");
    let error = read_capped(&path).expect_err("a file over the ceiling must be refused");
    assert!(
        matches!(error, MavenError::TooLarge { .. }),
        "expected a size refusal, got {error:?}"
    );
}

/// **The depth ceiling — the row that a wrong belief about the crate would
/// have failed.**
///
/// The first version of this row nested `MAX_NODES + 1` deep and asserted the
/// refusal came from `nodes_limit`. It aborted the process instead: `roxmltree`
/// appends an element's node on its *closing* tag (`parse.rs:781`), so the
/// recursion has already gone as deep as the document nests before any node
/// exists to count, and `nodes_limit` is consulted on the way back out. 2049
/// levels was enough to exhaust a 2 MiB stack.
///
/// So the ceiling this asserts is [`MAX_DEPTH`], and it is enforced on the text
/// before the parser is involved. *Red by:* removing [`check_depth`], which
/// fails **cleanly** on the assertion — a row deep enough to actually overflow
/// would take every other row in the binary with it, and that is a worse
/// measurement than a clean red.
///
/// *Red by:* `nodes_limit: u32::MAX`, which stops being a depth ceiling at all.
#[test]
fn a_document_past_the_depth_ceiling_is_refused_before_the_parser_sees_it() {
    let text = deeply_nested(MAX_DEPTH + 1);
    let error = parse_settings(&text).expect_err("past the ceiling must be refused");
    match &error {
        MavenError::TooDeep { reason } => assert!(reason.contains("64"), "{error}"),
        other => panic!("expected a depth refusal, got {other:?}"),
    }
}

/// The breadth ceiling, which is what `nodes_limit` actually is.
///
/// A sibling list is the shape it exists for: a document can be enormous and
/// perfectly flat, and this is the ceiling that catches it.
///
/// *Red by:* `nodes_limit: u32::MAX`, or raising `MAX_NODES` past the document.
#[test]
fn a_document_past_the_node_ceiling_is_refused() {
    let text = wide(MAX_NODES as usize + 16);
    let error = parse_settings(&text).expect_err("past the ceiling must be refused");
    match &error {
        MavenError::TooDeep { reason } => assert!(reason.contains("2048"), "{error}"),
        other => panic!("expected a node refusal, got {other:?}"),
    }
}

/// **The other half of the depth pair: a ceiling that refuses everything is not
/// a ceiling.**
///
/// Real nesting for Maven is about ten (`settings > profiles > profile >
/// repositories > repository > releases > enabled`), and this asserts a
/// document well inside 64 still parses — so a `MAX_DEPTH` lowered to something
/// small and defensive is caught here rather than by a user whose
/// `settings.xml` stopped being read.
///
/// *Red by:* lowering `MAX_DEPTH` below real-world nesting.
#[test]
fn a_document_inside_both_ceilings_is_still_read() {
    let parsed = parse_settings(&deeply_nested(4)).expect("a shallow document parses");
    assert!(parsed.servers.is_empty());
    let flat = parse_settings(&wide(32)).expect("a narrow document parses");
    assert_eq!(flat.local_repository, None);
}

/// A `<` inside a comment is not an element, and `settings.xml` files are full
/// of commented-out examples — a commented profile block nested eight deep is
/// ordinary content, not an attack.
///
/// **The comment is nested past `MAX_DEPTH` on purpose, and that is the whole
/// row.** The first version put forty levels in it, which is below the ceiling
/// of 64 — so a scanner that *does* read comment contents never exceeds the
/// limit and the row stayed green through a full campaign. It looked like a
/// survivor and was a defective row: a row that cannot fail is not evidence, it
/// is decoration. A scanner that reads a comment's contents now refuses a
/// perfectly ordinary file, and this catches it.
///
/// *Red by:* scanning a comment's contents instead of skipping it.
#[test]
fn markup_inside_a_comment_or_cdata_does_not_count_towards_the_depth() {
    let deep_in_comment = "<a>".repeat(MAX_DEPTH + 10);
    let text = format!(
        "<settings><!-- {deep_in_comment} -->
  <![CDATA[<b><b><b>]]>
  <servers><server><id>ok</id></server></servers>
</settings>"
    );
    let parsed = parse_settings(&text).expect("comments are not elements");
    assert_eq!(parsed.servers[0].id, "ok");
}

/// A `>` inside a quoted attribute value does not end the tag.
///
/// This is why [`check_depth`] is quote-aware rather than a `<` counter, and
/// getting the row to *discriminate* took two attempts worth recording.
///
/// The first attempt used `<a b="x>y">`. A scanner that stops at the `>` inside
/// the quotes ends that tag early — but it still counts exactly one opening
/// tag, so the depth comes out the same and the row stayed green through a
/// campaign. **The mutation had bitten and the row could not see it.** A green
/// row here would have been a statement about my test rather than about the
/// scanner.
///
/// The case that does discriminate puts a closing tag *inside* the attribute
/// value, which is where the two readings genuinely diverge:
///
/// - quote-aware: `<a b="q></a>">` is **one** opening tag, so 70 of them is
///   depth 70 — over [`MAX_DEPTH`], refused.
/// - naive: the tag ends at the first `>`, leaving `</a>` to be read as a real
///   closing tag, so each occurrence nets **zero** and the document measures as
///   flat.
///
/// 70 levels is also deep enough for `roxmltree` itself to survive if the check
/// ever stopped firing, so this row fails by assertion rather than by aborting
/// the test binary.
///
/// *Red by:* skipping a tag with a plain `position(|b| b == b'>')`.
#[test]
fn a_gt_inside_an_attribute_value_does_not_end_the_tag() {
    let text = format!("<settings>{}</settings>", r#"<a b="q></a>">"#.repeat(70));
    // 70 real levels: over `MAX_DEPTH`. Were the scanner naive, this document
    // would measure as flat and parse — and the row fails on the missing
    // refusal.
    let error = parse_settings(&text).expect_err("70 real levels is over the ceiling");
    assert!(
        matches!(error, MavenError::TooDeep { .. }),
        "expected a depth refusal, got {error:?}"
    );
}

/// `<servers>` nested under a handful of `<a>` tags is still `<servers>`,
/// because the walk is over direct children of the root — the depth comes from
/// wrapping the root, not from burying the servers.
fn deeply_nested(depth: usize) -> String {
    let mut text = String::new();
    for _ in 0..depth {
        text.push_str("<a>");
    }
    text.push_str("<settings><servers><server><id>deep</id></server></servers></settings>");
    for _ in 0..depth {
        text.push_str("</a>");
    }
    text
}

/// A perfectly flat document, which is the shape `MAX_NODES` exists for.
fn wide(count: usize) -> String {
    let mut text = String::from("<settings>");
    for _ in 0..count {
        text.push_str("<a></a>");
    }
    text.push_str("</settings>");
    text
}

/// `${env.X}` is named and **not resolved**, and the file's text is not
/// mistaken for the credential it stands for.
///
/// Two claims, one row, because the first is worthless without the second: a
/// report that correctly says "this comes from `$ACME_DEPLOY_TOKEN`" and also
/// says "password is 19 bytes" has told the operator a number about a secret it
/// never saw.
///
/// *Red by:* restoring `password.map(|value| value.len())` — the row then fails
/// on `password_len` being `Some(19)`.
#[test]
fn an_env_reference_is_named_never_resolved_and_never_measured() {
    let discovery = report(&settings());
    let server = &discovery.files[0].servers[1];
    assert_eq!(server.id, "acme-from-env");
    assert!(server.password_is_env_reference);
    assert_eq!(server.env_reference.as_deref(), Some("ACME_DEPLOY_TOKEN"));
    assert_eq!(
        server.password_len, None,
        "the report measured the text `{PASSWORD}`-style placeholder instead of the credential"
    );
}

/// The environment is the **caller's**, not the file's, so the name is reported
/// and nothing is looked up.
///
/// This row also pins the property that a resolver here would have to break:
/// the test process's own variables are visible to it, so a resolver that
/// *worked* would find `ACME_DEPLOY_TOKEN` set and produce a value.
///
/// *Red by:* any code that calls `std::env::var` on the reported name.
#[test]
fn the_environment_is_never_read_to_resolve_a_reference() {
    // Set deliberately: if anything in the parse path resolved `${env.…}`, this
    // variable is what it would find.
    std::env::set_var("ACME_DEPLOY_TOKEN", "a-value-the-report-must-never-contain");
    let parsed = parse_settings(&settings()).expect("parses");
    let rendered = format!("{:?}", parsed);
    assert!(
        !rendered.contains("a-value-the-report-must-never-contain"),
        "the environment was read: {rendered}"
    );
    std::env::remove_var("ACME_DEPLOY_TOKEN");
}

/// "No password" is not "a password of length zero", and only one of the two is
/// a thing the file said.
///
/// *Red by:* `child_text(node, "password").map(...).unwrap_or(Some(0))`, or a
/// `length: usize` field instead of an `Option`.
#[test]
fn a_server_with_no_password_reports_none_rather_than_zero() {
    let discovery = report(&settings());
    let server = &discovery.files[0].servers[2];
    assert_eq!(server.id, "acme-anonymous");
    assert_eq!(server.password_len, None);
    assert_eq!(server.username_len, None);
    assert!(!server.password_is_env_reference);
    assert!(server.env_reference.is_none());
}

/// The `<id>` is reported **verbatim**, and that is a deliberate asymmetry with
/// the username.
///
/// `<id>` is the handle a `pom.xml` references — Maven's audience, and the one
/// field without which the report cannot be acted on. It is not a secret: the
/// tool already carries it in the clear, in every build log that has ever
/// resolved an artifact.
///
/// *Red by:* shortening the id to a length, or omitting it.
#[test]
fn an_id_is_reported_verbatim_because_a_pom_refers_to_it() {
    let discovery = report(&settings());
    assert_eq!(discovery.files[0].servers[0].id, "acme-releases");
    let json = serde_json::to_string(&discovery.into_discovery()).expect("serialises");
    assert!(
        json.contains(r#""id":"acme-releases""#),
        "the audience is missing from the report: {json}"
    );
}

/// A `<port>` that is not a port is absent, not zero and not 65535.
///
/// The file says `70000`; the report says "no port". A number in the report has
/// to be a number the tool could actually use, and `0` would be a *different*
/// wrong claim from `None` — it is a real port.
///
/// *Red by:* `.and_then(|v| v.parse().ok()).unwrap_or(0)`.
#[test]
fn a_port_that_is_not_a_port_is_absent_rather_than_zero() {
    let text =
        "<settings><proxies><proxy><id>p</id><port>70000</port></proxy></proxies></settings>";
    let parsed = parse_settings(text).expect("parses");
    assert_eq!(parsed.proxies[0].port, None);
    assert_eq!(parsed.proxies[0].host, None);
}

/// The converse: a port that *is* a port survives, and a real proxy is fully
/// described. Paired with the row above so neither can pass by accident.
#[test]
fn a_real_proxy_is_fully_described() {
    let discovery = report(&settings());
    let proxy = &discovery.files[0].proxies[0];
    assert_eq!(proxy.id, "acme-proxy");
    assert_eq!(proxy.protocol.as_deref(), Some("https"));
    assert_eq!(proxy.host.as_deref(), Some("proxy.acme.test"));
    assert_eq!(proxy.port, Some(3128));
    assert!(proxy.active);
    assert_eq!(proxy.password_len, Some(14));
}

/// Matching is by **local name**, so a file that omits the namespace still
/// parses and a file that has one still parses.
///
/// Both halves matter, and they fail in opposite directions: matching only the
/// namespaced form finds nothing in an unnamespaced file, and that silence
/// reads exactly like "you have no credentials".
///
/// *Red by:* comparing `tag_name().namespace()` instead of `.name()`.
#[test]
fn a_document_without_the_namespace_still_parses() {
    let text = "<settings><servers><server><id>plain</id></server></servers></settings>";
    let parsed = parse_settings(text).expect("parses");
    assert_eq!(parsed.servers[0].id, "plain");
}

/// **A mirror URL is a credential more often than anyone expects.**
///
/// `https://token@github.com/...` is a documented, supported Maven form, and
/// `https://user:password@repo.acme.test/maven` is worse. The report is the
/// artefact in R3 that travels furthest before anything is written, so the
/// userinfo is removed and only its size survives — the same trade `<password>`
/// gets.
///
/// *Red by:* printing `child_text(mirror, "url")` unstripped.
///
/// Asserted on the serialised JSON, like every other leak row, because the
/// leak is in what a caller receives rather than in what the struct holds.
#[test]
fn a_mirror_url_with_embedded_credentials_is_reported_without_them() {
    let text = "<settings><mirrors><mirror><id>m</id>\
        <url>https://deploy-bot:hunter2-not-a-real-secret@repo.acme.test/maven</url>\
        </mirror></mirrors></settings>";
    let discovery = report(text);
    let mirror = &discovery.files[0].mirrors[0];

    assert_eq!(mirror.id, "m");
    assert_eq!(
        mirror.url.as_deref(),
        Some("https://repo.acme.test/maven"),
        "the userinfo was not removed"
    );
    assert_eq!(
        mirror.url_credential_len,
        Some("deploy-bot:hunter2-not-a-real-secret".len())
    );

    let json = serde_json::to_string(&discovery.into_discovery()).expect("serialises");
    assert!(
        !json.contains("hunter2-not-a-real-secret"),
        "the URL credential reached the report: {json}"
    );
    assert!(
        !json.contains("deploy-bot"),
        "the URL username reached the report: {json}"
    );
}

/// An `@` in a path is not a credential, and an `@` in the password is still
/// one credential rather than two.
///
/// Both halves, because a split on the *first* `@` gets the second case wrong
/// and a split on any `@` outside the authority gets the first wrong — and the
/// first failure mode is a URL silently mangled into something no resolver
/// accepts.
///
/// *Red by:* splitting on the first `@` anywhere in the string.
#[test]
fn an_at_sign_outside_the_authority_is_not_treated_as_a_credential() {
    let text = "<settings><mirrors><mirror><id>m</id>\
        <url>https://user:p@ss@repo.acme.test/team@acme/maven</url>\
        </mirror></mirrors></settings>";
    let mirror = &report(text).files[0].mirrors[0].clone();
    assert_eq!(
        mirror.url.as_deref(),
        Some("https://repo.acme.test/team@acme/maven"),
        "the path was mangled or the password was split wrongly"
    );
    assert_eq!(mirror.url_credential_len, Some("user:p@ss".len()));
}

/// A `<proxy>` with no `<active>` is **inactive**, because that is what Maven
/// does with it.
///
/// The opposite default is the dangerous one: a report that says a proxy is
/// live when the file never said so is an operator acting on a credential path
/// Maven will not take.
///
/// *Red by:* `.unwrap_or(true)`.
#[test]
fn a_proxy_without_an_active_element_is_inactive_rather_than_active() {
    let text = "<settings><proxies><proxy><id>p</id><host>h.test</host>\
        <port>8080</port></proxy></proxies></settings>";
    let parsed = parse_settings(text).expect("parses");
    assert!(!parsed.proxies[0].active);
    assert_eq!(parsed.proxies[0].host.as_deref(), Some("h.test"));
    assert_eq!(parsed.proxies[0].port, Some(8080));
}

/// A refusal is the one path that formats something *we* wrote next to
/// something the file wrote, so it is the path where a credential could arrive
/// without anyone deciding to put it there.
///
/// Both renderings are asserted: `Display` for the message an operator reads,
/// and `Debug` for the `{error:?}` an operator pastes into an issue.
///
/// *Red by:* including the document text in the reason — which reads as
/// *better diagnostics* right up until it is not.
#[test]
fn a_refusal_message_carries_no_value() {
    // Malformed *and* carrying the marker: `</servers>` closes what `<server>`
    // opened, so the parser stops at a point well after the text it must not
    // repeat. A well-formed document would have produced no refusal at all,
    // which is a different row entirely.
    let text = format!("<settings><servers><server><id>{PASSWORD}</id></servers></settings>");
    let error = parse_settings(&text).expect_err("this document is malformed");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains(PASSWORD),
            "a refusal carried a value: {rendered}"
        );
    }
}

/// A `<mirror>` with no url reports none. Nothing is invented to fill a gap the
/// file left.
///
/// *Red by:* `unwrap_or_default()` into a `String`.
#[test]
fn a_mirror_without_a_url_is_not_invented() {
    let text = "<settings><mirrors><mirror><id>bare</id></mirror></mirrors></settings>";
    let parsed = parse_settings(text).expect("parses");
    assert_eq!(parsed.mirrors[0].id, "bare");
    assert_eq!(parsed.mirrors[0].url, None);
    assert_eq!(parsed.mirrors[0].url_credential_len, None);
    assert_eq!(parsed.mirrors[0].mirror_of, None);
}

/// A `<localRepository>` is a path, not a credential, and is reported as
/// itself — this is the one value in the file printed verbatim.
///
/// *Red by:* opaque-treating `localRepository` along with the passwords.
#[test]
fn the_local_repository_is_reported_as_itself() {
    let discovery = report(&settings());
    assert_eq!(
        discovery.files[0].local_repository.as_deref(),
        Some("/var/cache/m2")
    );
}

/// **The anti-orphan row.**
///
/// R3.A.2 reported forty green tests while the module they lived in was not
/// compiled by anyone, because the tracked `lib.rs` came back from a concurrent
/// release without the `pub mod` line and the new files were untracked. The
/// suite was green and the feature was absent.
///
/// This row cannot be green in that state: `into_discovery` is the only way a
/// Maven report reaches the envelope the CLI prints, so the row **is** the
/// product surface. A `maven` module unreachable from `AnyReport` cannot
/// produce a `Discovery`.
///
/// *Red by:* deleting the `AnyReport::Maven` variant, or `into_discovery`.
#[test]
fn the_maven_report_reaches_the_envelope_the_cli_prints() {
    let discovery = report(&settings()).into_discovery();
    assert_eq!(discovery.family, "maven");
    assert_eq!(discovery.schema, crate::DISCOVERY_SCHEMA);
    let json = serde_json::to_string(&discovery).expect("serialises");
    assert!(
        json.contains(r#""maven""#),
        "the family has no envelope variant: {json}"
    );

    // And it round-trips, because a report an agent cannot hand back to the
    // next command is half a contract. `plan` reads a report back for `adopt`.
    let back: crate::Discovery = serde_json::from_str(&json).expect("round-trips");
    assert_eq!(back.family, "maven");
}

// ── The rows that go through `discover`, not `parse_settings` ──────────────
//
// These need real files, because what they measure is the *policy* around a
// refusal, and a refusal is a decision about a path on disk.

fn write_settings(home: &std::path::Path, text: &str) -> std::path::PathBuf {
    let dir = home.join(".m2");
    std::fs::create_dir_all(&dir).expect("creates");
    let path = dir.join("settings.xml");
    std::fs::write(&path, text).expect("writes");
    path
}

/// **The policy this family has and npm does not: refuse the *file*, keep the
/// report.**
///
/// A world-writable `settings.xml` is refused by the fingerprint — anything
/// another user can rewrite is a report an operator can act on by mistake. The
/// question this row answers is what happens to the *rest* of the run: the
/// answer is a finding, and no file is claimed.
///
/// *Red by:* pushing the file into `files` anyway, or dropping the finding.
#[test]
fn a_world_writable_settings_file_is_refused_and_reported_as_a_finding() {
    let home = tempfile::tempdir().expect("a scratch dir");
    let path = write_settings(home.path(), &settings());

    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmods");

    let report = Maven
        .discover(&FingerprintPolicy::strict(), home.path(), home.path())
        .expect("discovery succeeds; the refusal is a finding, not a failure");

    assert!(
        report.files.is_empty(),
        "a refused file was described: {report:?}"
    );
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].severity, crate::Severity::Refused);
    assert!(
        report.findings[0].subject.contains("settings.xml"),
        "{:?}",
        report.findings[0]
    );
}

/// **Absence is not a finding.**
///
/// Most machines have no `~/.m2/settings.xml` at all, and telling an operator
/// about every one of them would be noise. This row is the negative of the one
/// above, and it exists because a version that pushed a finding on every
/// absence would satisfy the first row by being simply broken.
///
/// *Red by:* pushing a finding when `candidate.path.exists()` is false.
#[test]
fn a_machine_with_no_settings_file_gets_an_empty_report_and_no_findings() {
    let home = tempfile::tempdir().expect("a scratch dir");
    let report = Maven
        .discover(&FingerprintPolicy::strict(), home.path(), home.path())
        .expect("discovery succeeds");
    assert!(report.files.is_empty());
    assert!(
        report.findings.is_empty(),
        "absence was reported as something to act on: {report:?}"
    );
}

/// The candidate is the one file Maven actually reads at the user level.
///
/// **Not** a project-level `settings.xml`: Maven has no project-level settings
/// file, and offering one would produce a report about a file the tool never
/// opens. **Not** the installation's, because its path depends on where Maven
/// is installed and this crate does not read the environment.
///
/// *Red by:* adding a `Project` candidate, or resolving `$MAVEN_HOME` here.
#[test]
fn the_only_candidate_is_the_user_settings_file() {
    let candidates = Maven::candidates(
        std::path::Path::new("/home/u"),
        std::path::Path::new("/work/project"),
    );
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].path,
        std::path::Path::new("/home/u")
            .join(".m2")
            .join("settings.xml")
    );
    assert_eq!(candidates[0].origin, crate::Origin::User);
}

/// A malformed file is refused and the report survives — same policy as the
/// world-writable row, reached through the parse instead of the fingerprint.
///
/// *Red by:* propagating the parse error out of `discover` as `Err`.
#[test]
fn a_malformed_settings_file_is_refused_and_reported_as_a_finding() {
    let home = tempfile::tempdir().expect("a scratch dir");
    write_settings(home.path(), "<settings><servers></settings>");
    let report = Maven
        .discover(&FingerprintPolicy::strict(), home.path(), home.path())
        .expect("discovery succeeds");
    assert!(report.files.is_empty());
    assert_eq!(report.findings.len(), 1, "{report:?}");
}
