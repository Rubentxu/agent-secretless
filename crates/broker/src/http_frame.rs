//! How the bytes after an HTTP head are delimited — and a refusal for the ones
//! nobody can delimit unambiguously.
//!
//! # Why this module exists
//!
//! Two reasons, and only the second one was obvious when it was written.
//!
//! The obvious reason is that a CONNECT tunnel relays **one** request and then
//! sits there, which is the gap C2.8 is chartered to close. The naive fix is a
//! loop: read the next `\r\n\r\n`, substitute the bearer token, write it
//! upstream, repeat. That is wrong, and this module is why. `\r\n\r\n` frames a
//! head only when a head is what comes next — true of the *first* head on a
//! connection, false of every head after a request body, because a body can
//! contain `\r\n\r\n` itself. A naive loop would substitute a credential into
//! the middle of somebody's form post. Telling those apart means knowing where
//! each message ends, which means reading the framing headers.
//!
//! The reason that was not obvious: **ambiguous framing is a smuggling
//! primitive, and this parser is the place to refuse it.** A front end and a
//! tunnel that disagree about where a request ends is the whole of request
//! smuggling — one of them sees two requests where the other sees one, and the
//! credential in the second one belongs to a different user. A relay that copies
//! bytes without understanding framing does not create that disagreement, but it
//! is the component that will have to make the decision once it starts
//! substituting into a stream it is relaying.
//!
//! So every ambiguity is a refusal rather than a guess, in the same posture the
//! rest of this broker takes: a request it cannot frame is not forwarded. The
//! cases are enumerated in [`FrameError`], and each one is a shape that has been
//! used to smuggle.
//!
//! # What this module deliberately does not do
//!
//! It does not read from a socket, does not buffer, and does not own a
//! connection. It takes a byte slice that already contains a complete head and
//! answers two questions about it: where does the head end, and how is the body
//! after it delimited. Everything about *when* those bytes arrive belongs to
//! `tls_bridge`, which is where the two directions have to be pumped together.
//!
//! Keeping it pure is what makes the smuggling cases testable at all. Every test
//! below is a request someone can send, checked in a microsecond, with no
//! process, no port and no certificate.

use std::fmt;

/// Where a message's body ends, once its head has been read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body follows. A `GET`, a `204`, a `304`.
    None,
    /// Exactly this many bytes follow.
    Length(u64),
    /// `Transfer-Encoding: chunked`; the body is a chunked stream and has to be
    /// parsed rather than counted.
    ///
    /// Counted as a distinct case rather than folded into `Length` because the
    /// relay has to *understand* it: a chunked body cannot be relayed by byte
    /// count, and treating it as `UntilClose` would be wrong in the other
    /// direction — a chunked response does not need the connection closed.
    Chunked,
    /// The peer closes to signal the end. The only correct framing for a
    /// response with neither `Content-Length` nor `Transfer-Encoding`, and the
    /// one this parser falls back to for one.
    UntilClose,
}

impl Framing {
    /// Whether the relay can measure this framing without parsing it.
    ///
    /// The reason the type is split at all. A `Length` is a number the relay can
    /// budget against; a `Chunked` is a stream it would have to re-frame; a
    /// `UntilClose` is unbounded and is only acceptable on the response side of
    /// a message the peer has already said it will close.
    pub fn is_counted(&self) -> bool {
        matches!(self, Framing::Length(_))
    }
}

/// What a head says about the message it introduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// How the body after this head is delimited.
    pub framing: Framing,
    /// Whether the peer announced it will close the connection afterwards.
    ///
    /// Kept separate from [`Framing::UntilClose`] because the two are
    /// independent: a response can be `Content-Length: 0` *and* carry
    /// `Connection: close`, and a request can be `Content-Length: 12` on a
    /// connection that is about to close. A relay that conflated them would stop
    /// reusing connections that are perfectly reusable.
    pub close_after: bool,
    /// The response's status code, or `None` for a request head.
    ///
    /// Carried on the parsed head rather than re-read from the bytes at the call
    /// site, for the same reason the framing is: the loop that relays these
    /// messages must not hold a *second* opinion about what a head says. A relay
    /// that parsed the status once to frame the body and again to decide whether
    /// to keep reading is a relay with two parsers, and two parsers is the whole
    /// class of defect this module was written to remove.
    ///
    /// Needed for exactly two decisions, both of which a byte count cannot make:
    /// a `1xx` carries no body and is not the end of the exchange, and a `101`
    /// is not an HTTP message at all.
    pub status: Option<u16>,
    /// Bytes this head occupies, terminator included. The body starts here.
    pub len: usize,
}

/// Which of a message's two bounds was crossed.
///
/// A type rather than a `&'static str` in the variant, so that adding a third
/// bound is a compile error at the match rather than another string somebody has
/// to remember to change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// The head, and the limit that stops it being accumulated in memory.
    Head,
    /// The body, and the limit that stops one message being unbounded.
    Body,
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Head => f.write_str("request head"),
            Subject::Body => f.write_str("request body"),
        }
    }
}

/// Why a head could not be framed.
///
/// Every variant is a shape that has been used to smuggle a request past
/// something that reads framing differently, or a head this broker is not willing
/// to guess at. None of them is a client mistake to be tolerated quietly, because
/// tolerating them quietly is what the two-parsers disagreement is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A message is longer than this relay accepts.
    ///
    /// A bound rather than a trust decision, and it exists because the head is
    /// accumulated in memory while it is read. The broker refuses rather than
    /// truncates: a truncated head is a head whose framing this side guessed.
    ///
    /// **`subject` is not decoration.** One variant covers two limits that are
    /// different numbers answering different questions — how long a head may be,
    /// and how long a body may be — and the message used to name the head for
    /// both. A body over the limit was therefore reported as "the request head
    /// exceeds the limit", and an operator reading that goes to look at head
    /// sizes. The relay's own test caught it by asserting on the *reason* rather
    /// than on the failure.
    TooLarge { limit: usize, subject: Subject },

    /// The bytes before the terminator are not a head this parser understands.
    Malformed { detail: &'static str },

    /// Two headers that disagree, or the same header twice with different values.
    ///
    /// **This is the request-smuggling case.** `Content-Length` twice with
    /// different values, or `Content-Length` together with
    /// `Transfer-Encoding`, means the head describes two different message
    /// lengths and any two components reading it can disagree. A proxy that picks
    /// one and a backend that picks the other is a smuggled request. Refusing is
    /// the only answer that is correct for both, and it costs a client nothing:
    /// nothing that legitimately wants to send both headers does.
    Ambiguous { detail: &'static str },

    /// The framing is valid HTTP that this relay will not carry.
    Unsupported { detail: &'static str },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooLarge { limit, subject } => {
                write!(f, "the {subject} exceeds the {limit}-byte limit")
            }
            FrameError::Malformed { detail } => write!(f, "malformed HTTP head: {detail}"),
            FrameError::Ambiguous { detail } => write!(f, "ambiguous HTTP framing: {detail}"),
            FrameError::Unsupported { detail } => write!(f, "unsupported HTTP framing: {detail}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// The byte sequence that terminates a head.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Finds where a head ends in `buf`.
///
/// `Ok(None)` means "not yet" and is not an error: a head arrives in pieces and
/// the caller keeps what it has. A caller that treats it as a failure closes
/// every connection whose first read was short, which is a bug this function's
/// return type exists to make hard to write.
pub fn find_head_end(buf: &[u8], max: usize) -> Result<Option<usize>, FrameError> {
    match buf.windows(HEAD_END.len()).position(|w| w == HEAD_END) {
        Some(at) => {
            let len = at + HEAD_END.len();
            if len > max {
                return Err(FrameError::TooLarge {
                    limit: max,
                    subject: Subject::Head,
                });
            }
            Ok(Some(len))
        }
        // Checked before returning "not yet", because a head that has not
        // arrived yet and a head that will never be acceptable are different
        // answers and the caller keeps buffering on the first one.
        None if buf.len() > max => Err(FrameError::TooLarge {
            limit: max,
            subject: Subject::Head,
        }),
        None => Ok(None),
    }
}

/// Parses a **request** head.
///
/// The body length is checked against `max_body` so the relay can budget against
/// it before forwarding anything: a request that claims a gigabyte is refused at
/// the head rather than after the relay has already moved a gigabyte of the
/// client's bytes to the destination.
pub fn parse_request_head(head: &[u8], max_body: u64) -> Result<Head, FrameError> {
    let fields = Fields::of(head, true)?;
    if !fields.request_line.starts_with(b"GET ")
        && !fields.request_line.starts_with(b"HEAD ")
        && !fields.request_line.starts_with(b"POST ")
        && !fields.request_line.starts_with(b"PUT ")
        && !fields.request_line.starts_with(b"DELETE ")
        && !fields.request_line.starts_with(b"PATCH ")
        && !fields.request_line.starts_with(b"OPTIONS ")
        && !fields.request_line.starts_with(b"TRACE ")
    {
        return Err(FrameError::Unsupported {
            detail: "unrecognised request method",
        });
    }

    let framing = if fields.has("transfer-encoding") {
        if fields.len_of("content-length")?.is_some() {
            return Err(FrameError::Ambiguous {
                detail: "both Content-Length and Transfer-Encoding",
            });
        }
        if !fields.transfer_encoding_is_chunked() {
            return Err(FrameError::Unsupported {
                detail: "Transfer-Encoding is not chunked",
            });
        }
        Framing::Chunked
    } else {
        match fields.len_of("content-length")? {
            Some(n) => {
                if n > max_body {
                    return Err(FrameError::TooLarge {
                        limit: max_body as usize,
                        subject: Subject::Body,
                    });
                }
                Framing::Length(n)
            }
            // A request with no length headers has no body. That is the
            // specification's rule and it is the safe one: assuming a body that
            // is not there would make this parser disagree with a peer that
            // agrees with it, which is the failure this module exists to stop.
            None => Framing::None,
        }
    };

    Ok(Head {
        framing,
        close_after: fields.is_close(),
        status: None,
        len: head.len(),
    })
}

/// Parses a **response** head.
///
/// The status line matters in a way the request method does not: `1xx`, `204`
/// and `304` carry no body *whatever their headers say*, and a parser that
/// trusted a `Content-Length` on a `204` would wait for bytes that will never
/// come and hold the tunnel open until the client gave up.
pub fn parse_response_head(head: &[u8], max_body: u64) -> Result<Head, FrameError> {
    let fields = Fields::of(head, false)?;
    let status = fields.status_code().ok_or(FrameError::Malformed {
        detail: "no status code on the response line",
    })?;

    // "No body, whatever the headers say." Checked before the framing headers so
    // a `Content-Length` on a `304` — which is legal, and means the length the
    // *would-be* body had — does not become a wait.
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(Head {
            framing: Framing::None,
            close_after: fields.is_close(),
            status: Some(status),
            len: head.len(),
        });
    }

    let framing = if fields.has("transfer-encoding") {
        if fields.len_of("content-length")?.is_some() {
            return Err(FrameError::Ambiguous {
                detail: "both Content-Length and Transfer-Encoding",
            });
        }
        if !fields.transfer_encoding_is_chunked() {
            return Err(FrameError::Unsupported {
                detail: "Transfer-Encoding is not chunked",
            });
        }
        Framing::Chunked
    } else {
        match fields.len_of("content-length")? {
            Some(n) => {
                if n > max_body {
                    return Err(FrameError::TooLarge {
                        limit: max_body as usize,
                        subject: Subject::Body,
                    });
                }
                Framing::Length(n)
            }
            // No length and no chunking: the body ends when the peer closes. That
            // is the specification's rule, and it is the *only* correct answer —
            // refusing it would break a large share of real servers, and unlike
            // the ambiguous cases above there is nothing here for a second parser
            // to disagree about.
            None => Framing::UntilClose,
        }
    };

    Ok(Head {
        framing,
        close_after: fields.is_close(),
        status: Some(status),
        len: head.len(),
    })
}

/// Whether a request head asks for the body to wait for the origin's go-ahead.
///
/// `Expect: 100-continue` inverts the ordinary order: the client sends the head,
/// stops, and does not send the body until the origin answers. A relay that
/// forwards the head and then reads the body waits for bytes the client is
/// deliberately withholding, while the origin waits for a body that never
/// arrives. Nothing times out and nothing is refused — the tunnel simply hangs,
/// which is the worst of the available outcomes because it looks like a slow
/// server.
///
/// The answer is to *notice*, not to solve it here. Whether the origin accepts,
/// declines, or never answers is a conversation between the client and the
/// origin, and a relay that has to hold both directions open to take part in it
/// is a relay that is no longer a sequential pump. The caller refuses.
pub fn request_expects_continue(head: &[u8]) -> bool {
    Fields::of(head, true)
        .map(|fields| {
            fields
                .values("expect")
                .into_iter()
                .filter_map(|v| std::str::from_utf8(v).ok())
                .any(|v| v.trim().eq_ignore_ascii_case("100-continue"))
        })
        .unwrap_or(false)
}

/// Whether a request head asks to switch the connection to another protocol.
///
/// A `101` or a `CONNECT`-style upgrade turns the tunnel into a full-duplex byte
/// pipe for a protocol this relay does not frame and will not claim to. The same
/// reasoning as [`request_expects_continue`]: notice, and let the caller refuse
/// rather than half-participate.
pub fn request_declares_upgrade(head: &[u8]) -> bool {
    Fields::of(head, true)
        .map(|fields| fields.has("upgrade"))
        .unwrap_or(false)
}

/// A head split into its start line and its headers, with the header lookups the
/// two parsers need.
struct Fields<'a> {
    request_line: &'a [u8],
    headers: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Fields<'a> {
    fn of(head: &'a [u8], is_request: bool) -> Result<Self, FrameError> {
        let body_start = head
            .windows(HEAD_END.len())
            .position(|w| w == HEAD_END)
            .ok_or(FrameError::Malformed {
                detail: "the head has no terminator",
            })?;
        let mut lines = head[..body_start].split(|b| *b == b'\n');

        let start = lines.next().ok_or(FrameError::Malformed {
            detail: "empty head",
        })?;
        // Tolerated rather than required: a lone `\r` before the `\n` is what
        // every real client sends, and a parser that rejected it would reject
        // everything.
        let start = match start.strip_suffix(b"\r") {
            Some(trimmed) => trimmed,
            None => start,
        };
        if start.is_empty() {
            return Err(FrameError::Malformed {
                detail: "empty start line",
            });
        }
        if is_request {
            let mut parts = start.splitn(3, |b| *b == b' ');
            let method = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            // The version is parsed and discarded: this relay does not speak
            // HTTP/1.0 keep-alive differently, and rejecting a version it did not
            // recognise would be a refusal with no security value.
            let _version = parts.next().unwrap_or_default();
            if method.is_empty() || target.is_empty() {
                return Err(FrameError::Malformed {
                    detail: "the request line is not METHOD TARGET VERSION",
                });
            }
        }
        // For a response, the version is not checked here. `status_code` is the
        // single place that validates it, and a second check that disagrees with
        // it about what a version is would be a second parser — which is the
        // thing this module refuses to be.

        let mut headers = Vec::new();
        for line in lines {
            let line = match line.strip_suffix(b"\r") {
                Some(trimmed) => trimmed,
                None => line,
            };
            if line.is_empty() {
                continue;
            }
            // **Obsolete line folding is a refusal, not an unfold.** A header
            // continued on the next line is legal in HTTP/1.1 and has been used
            // to hide a second `Content-Length` from parsers that differ in
            // whether they unfold. Unfolding here would be picking a side of a
            // disagreement this parser exists to refuse.
            if line[0] == b' ' || line[0] == b'\t' {
                return Err(FrameError::Ambiguous {
                    detail: "obsolete line folding in a header",
                });
            }
            let colon = line
                .iter()
                .position(|b| *b == b':')
                .ok_or(FrameError::Malformed {
                    detail: "a header line has no colon",
                })?;
            headers.push((trim(&line[..colon]), trim(&line[colon + 1..])));
        }

        Ok(Self {
            request_line: start,
            headers,
        })
    }

    fn has(&self, name: &'static str) -> bool {
        !self.values(name).is_empty()
    }

    /// The values of every header with this name, in the order they were sent.
    ///
    /// An iterator rather than a lookup, and that is the point: `Content-Length`
    /// twice is not an error to be smoothed over by taking the first, it is the
    /// question the whole module exists to ask.
    ///
    /// `name` is `&'static str` so the comparison captures nothing borrowed from
    /// the caller. Every call site passes a literal, and the alternative was a
    /// lifetime the returned iterator had to carry for no benefit.
    ///
    /// A `Vec` rather than a lazy iterator, and not for a reason about
    /// allocation: an `impl Iterator` over a borrow of `self` cannot be written
    /// without naming a lifetime the caller has no reason to care about, and the
    /// header list is a handful of entries read once per message.
    fn values(&self, name: &'static str) -> Vec<&'a [u8]> {
        self.headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, value)| *value)
            .collect()
    }

    /// The `Content-Length`, refusing anything that is not exactly one of them.
    ///
    /// Two headers with the *same* value is accepted, because the specification
    /// allows a sender to repeat it and two readers that both see `5` cannot
    /// disagree. Two with different values is the smuggling case and is refused
    /// by the `values` count below rather than by trusting the first one — which
    /// is what a lenient parser does, and why a lenient parser is the bug.
    fn len_of(&self, name: &'static str) -> Result<Option<u64>, FrameError> {
        let mut seen: Option<u64> = None;
        for value in self.values(name) {
            let n = parse_length(value)?;
            match seen {
                Some(previous) if previous != n => {
                    return Err(FrameError::Ambiguous {
                        detail: "Content-Length repeated with a different value",
                    })
                }
                _ => seen = Some(n),
            }
        }
        Ok(seen)
    }

    fn transfer_encoding_is_chunked(&self) -> bool {
        // The last encoding wins, per the specification — and the *only* case
        // this relay carries. `gzip, chunked` is chunked; `chunked, gzip` is not,
        // and forwarding the second while believing the first is a disagreement
        // with the peer about where the body ends.
        self.values("transfer-encoding")
            .into_iter()
            .filter_map(|v| std::str::from_utf8(v).ok())
            .flat_map(|v| v.split(','))
            .filter_map(|token| token.trim().rsplit(';').next())
            .filter_map(|token| std::str::from_utf8(token.as_bytes()).ok())
            .next_back()
            .map(|last| last.trim().eq_ignore_ascii_case("chunked"))
            .unwrap_or(false)
    }

    fn is_close(&self) -> bool {
        self.values("connection").into_iter().any(|v| {
            std::str::from_utf8(v)
                .map(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
                .unwrap_or(false)
        })
    }

    fn status_code(&self) -> Option<u16> {
        let mut parts = self.request_line.splitn(3, |b| *b == b' ');
        let version = parts.next()?;
        if !version.starts_with(b"HTTP/1.") {
            return None;
        }
        std::str::from_utf8(parts.next()?).ok()?.parse::<u16>().ok()
    }
}

fn parse_length(value: &[u8]) -> Result<u64, FrameError> {
    // A list value — `Content-Length: 5, 5` — is refused rather than
    // normalised. A peer that can be made to send two lengths is a peer this
    // parser declines to reason about.
    if value.contains(&b',') {
        return Err(FrameError::Ambiguous {
            detail: "Content-Length carries a list",
        });
    }
    // A leading `+`, a leading zero and a sign are all refused. `+5`, `05` and
    // ` 5` parse as numbers in most parsers and not in all of them, which is the
    // disagreement this module exists to prevent.
    if !value.first().is_some_and(|b| b.is_ascii_digit()) {
        return Err(FrameError::Malformed {
            detail: "Content-Length is not a number",
        });
    }
    if value.len() > 1 && value[0] == b'0' {
        return Err(FrameError::Ambiguous {
            detail: "Content-Length has a leading zero",
        });
    }
    // **One message for the whole class.** There were two — "does not start with
    // a digit" and "does not parse" — and the difference between them tells an
    // operator nothing while giving a reader two strings to match on. A refusal
    // reason that varies with how a value happened to fail is the same mistake
    // as a class derived from a rendered message.
    std::str::from_utf8(value)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(FrameError::Malformed {
            detail: "Content-Length is not a number",
        })
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|at| at + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(head: &str) -> Result<Head, FrameError> {
        let bytes = head.as_bytes();
        parse_request_head(bytes, 1024 * 1024)
    }

    fn response(head: &str) -> Result<Head, FrameError> {
        let bytes = head.as_bytes();
        parse_response_head(bytes, 1024 * 1024)
    }

    // --- finding the end of a head -----------------------------------------

    #[test]
    fn a_head_that_has_not_arrived_yet_is_not_an_error() {
        // The distinction the return type exists for. Returning an error here
        // would close every connection whose first read was short, which is
        // every connection on a slow network.
        assert_eq!(
            find_head_end(b"GET / HTTP/1.1\r\nHost: ex", 8 * 1024),
            Ok(None)
        );
        assert_eq!(find_head_end(b"", 8 * 1024), Ok(None));
    }

    #[test]
    fn a_complete_head_reports_its_length_terminator_included() {
        let head = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
        assert_eq!(find_head_end(head, 8 * 1024), Ok(Some(head.len())));
    }

    #[test]
    fn a_head_over_the_limit_is_refused_even_before_it_terminates() {
        // Before it terminates, and not only after: a peer that never sends the
        // terminator would otherwise grow this buffer without bound, and the
        // refusal is what stops it.
        let endless = vec![b'a'; 64];
        assert_eq!(
            find_head_end(&endless, 32),
            Err(FrameError::TooLarge {
                limit: 32,
                subject: Subject::Head,
            })
        );
    }

    #[test]
    fn a_complete_head_over_the_limit_is_refused_too() {
        // **This test did not exist until the falsification campaign deleted the
        // refusal and left the suite green.** `find_head_end` has two ways to
        // discover the head is too large — it terminated and is over, or it did
        // not terminate and the buffer is over — and the one above only ever
        // reached the second. A branch no test reaches is a branch that can be
        // removed, and this one could be: it returned "not yet" for a head that
        // was already known to be unacceptable, so a peer could send a finished
        // 8 KiB-plus head and the relay would have buffered it forever.
        let mut oversized = vec![b'a'; 64];
        oversized.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            find_head_end(&oversized, 32),
            Err(FrameError::TooLarge {
                limit: 32,
                subject: Subject::Head,
            })
        );
    }

    // --- request framing ----------------------------------------------------

    #[test]
    fn a_request_with_no_length_headers_has_no_body() {
        let head = request("GET /x HTTP/1.1\r\nHost: example.test\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::None);
    }

    #[test]
    fn a_content_length_is_the_body() {
        let head = request("POST /x HTTP/1.1\r\nContent-Length: 12\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::Length(12));
        assert!(head.framing.is_counted());
    }

    #[test]
    fn a_chunked_request_is_chunked_and_not_counted() {
        let head =
            request("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::Chunked);
        assert!(!head.framing.is_counted());
    }

    #[test]
    fn the_last_transfer_encoding_is_the_one_that_counts() {
        // `gzip, chunked` is chunked. Getting this backwards is a disagreement
        // with the peer about where the body ends.
        let head = request("POST /x HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .expect("framed");
        assert_eq!(head.framing, Framing::Chunked);

        // …and `chunked, gzip` is not, so it is refused rather than carried on
        // the strength of the first token.
        assert!(matches!(
            request("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
            Err(FrameError::Unsupported { .. })
        ));
    }

    // --- the smuggling cases ------------------------------------------------

    #[test]
    fn content_length_twice_with_different_values_is_refused() {
        // The canonical smuggling head. A parser that takes the first value and
        // a parser that takes the last disagree, and the disagreement *is* the
        // smuggled request.
        assert_eq!(
            request("POST /x HTTP/1.1\r\nContent-Length: 6\r\nContent-Length: 44\r\n\r\n"),
            Err(FrameError::Ambiguous {
                detail: "Content-Length repeated with a different value"
            })
        );
    }

    #[test]
    fn content_length_twice_with_the_same_value_is_accepted() {
        // The specification allows a sender to repeat it, and two readers that
        // both see `5` cannot disagree — so refusing this would cost a client
        // compatibility for no security gain.
        let head = request("POST /x HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n")
            .expect("framed");
        assert_eq!(head.framing, Framing::Length(5));
    }

    #[test]
    fn content_length_alongside_transfer_encoding_is_refused() {
        assert_eq!(
            request("POST /x HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(FrameError::Ambiguous {
                detail: "both Content-Length and Transfer-Encoding"
            })
        );
    }

    #[test]
    fn a_folded_header_is_refused_rather_than_unfolded() {
        // A continuation line is legal in HTTP/1.1 and has been used to hide a
        // second Content-Length from parsers that differ in whether they unfold.
        // Unfolding here would be picking a side of that disagreement.
        assert_eq!(
            request("POST /x HTTP/1.1\r\nContent-Length: 6\r\n\t, 44\r\n\r\n"),
            Err(FrameError::Ambiguous {
                detail: "obsolete line folding in a header"
            })
        );
    }

    #[test]
    fn a_content_length_some_other_parser_could_read_differently_is_refused() {
        // Each of these is read as a number by at least one parser and not by
        // another. **The property under test is the refusal, not which refusal**,
        // so this asserts `Err` and not a variant — and the reason each one gets
        // has its own test below. Asserting a variant here would have been a
        // test that quietly pinned the *order* of the checks, which is an
        // implementation detail that is free to change and expensive to notice.
        //
        // Whitespace around the value is deliberately not in this list: the
        // specification requires it stripped, every conforming parser strips it,
        // and a parser that disagreed about it would be the rare one.
        for hostile in [
            "+6",
            "0x6",
            "06",
            "six",
            "6.0",
            "-1",
            "6 6",
            "9999999999999999999999",
        ] {
            assert!(
                request(&format!(
                    "POST /x HTTP/1.1\r\nContent-Length: {hostile}\r\n\r\n"
                ))
                .is_err(),
                "`{hostile}` was accepted, and it is a length some other parser reads differently"
            );
        }
    }

    #[test]
    fn a_content_length_that_is_not_a_number_at_all_is_malformed() {
        // The one that has no reading anywhere, as distinct from the ones with
        // two. Keeping them apart is what lets an operator tell "this client is
        // broken" from "this client is trying something".
        for junk in ["six", "+6", "6.0", "-1", "6 6"] {
            assert_eq!(
                request(&format!(
                    "POST /x HTTP/1.1\r\nContent-Length: {junk}\r\n\r\n"
                )),
                Err(FrameError::Malformed {
                    detail: "Content-Length is not a number"
                }),
                "`{junk}` did not get the malformed refusal"
            );
        }
    }

    #[test]
    fn a_content_length_with_a_leading_zero_is_refused_as_ambiguous() {
        // A separate test because it is a different refusal with a different
        // reason, and lumping it in with the malformed cases would have hidden
        // which is which. `06` is a perfectly good number; the problem is that
        // another parser is free to read it as `6` and as octal, and two parsers
        // reading one header two ways is the whole of the bug.
        assert_eq!(
            request("POST /x HTTP/1.1\r\nContent-Length: 06\r\n\r\n"),
            Err(FrameError::Ambiguous {
                detail: "Content-Length has a leading zero"
            })
        );
        // A single `0` is not a leading zero, and refusing it would refuse
        // every empty-body POST.
        let head = request("POST /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::Length(0));
    }

    #[test]
    fn a_content_length_carrying_a_list_is_refused() {
        assert_eq!(
            request("POST /x HTTP/1.1\r\nContent-Length: 5, 6\r\n\r\n"),
            Err(FrameError::Ambiguous {
                detail: "Content-Length carries a list"
            })
        );
    }

    // --- response framing ---------------------------------------------------

    #[test]
    fn a_response_with_no_framing_headers_runs_until_the_peer_closes() {
        // The specification's rule, and the only correct one: refusing it would
        // break a large share of real servers, and unlike the cases above there
        // is nothing here for a second parser to disagree about.
        let head = response("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::UntilClose);
    }

    #[test]
    fn a_status_that_forbids_a_body_ignores_its_own_content_length() {
        // A `304` may carry the length the body *would* have had. Believing it
        // would wait for bytes that never come and hold the tunnel open.
        for status in ["204 No Content", "304 Not Modified", "100 Continue"] {
            let head = response(&format!(
                "HTTP/1.1 {status}\r\nContent-Length: 1024\r\n\r\n"
            ))
            .expect("framed");
            assert_eq!(
                head.framing,
                Framing::None,
                "{status} was given a body to wait for"
            );
        }
    }

    #[test]
    fn connection_close_is_separate_from_the_framing() {
        // Conflating the two would stop reusing connections that are perfectly
        // reusable, and would stop believing a `Content-Length: 0` on a
        // connection that is about to close.
        let head = response("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("framed");
        assert_eq!(head.framing, Framing::Length(0));
        assert!(head.close_after);
    }

    #[test]
    fn a_body_larger_than_the_budget_is_refused_at_the_head() {
        // Refused before a byte is forwarded, not after the relay has already
        // moved the client's claim to the destination.
        //
        // **And the subject is `Body`, which is the half this test now pins.**
        // It used to assert a message that named the head, and the message was
        // wrong: the head is 60-odd bytes and perfectly within any bound. A body
        // over the limit reported as an over-long head sends an operator to look
        // at the wrong number.
        assert_eq!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n", 1024),
            Err(FrameError::TooLarge {
                limit: 1024,
                subject: Subject::Body,
            })
        );
    }

    /// The distinction itself, in one place.
    ///
    /// The head bound and the body bound are enforced in different functions —
    /// `find_head_end` while the head is being accumulated, the parsers once it
    /// is whole — and they used to share one message. A test that asserted each in
    /// isolation could not tell that they had been confused for one another; this
    /// one puts them side by side, and the point is that they do not match.
    #[test]
    fn the_head_bound_and_the_body_bound_are_reported_differently() {
        let over_long_head = vec![b'x'; 2048];
        assert_eq!(
            find_head_end(&over_long_head, 1024),
            Err(FrameError::TooLarge {
                limit: 1024,
                subject: Subject::Head,
            }),
            "an unterminated head over the bound is a head problem"
        );
        assert_eq!(
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n", 1024),
            Err(FrameError::TooLarge {
                limit: 1024,
                subject: Subject::Body,
            }),
            "a declared length over the bound is a body problem, and it is the \
             message an operator reads to know which number to go and look at"
        );
    }

    // --- the shapes that are not heads at all -------------------------------

    #[test]
    fn a_line_without_a_colon_is_not_a_header() {
        assert!(matches!(
            request("GET /x HTTP/1.1\r\nHost example.test\r\n\r\n"),
            Err(FrameError::Malformed { .. })
        ));
    }

    #[test]
    fn a_request_line_that_is_not_method_target_version_is_refused() {
        assert!(matches!(
            request("GET\r\nHost: x\r\n\r\n"),
            Err(FrameError::Malformed { .. })
        ));
    }

    #[test]
    fn a_status_line_that_is_not_http_is_refused() {
        assert!(matches!(
            response("ICY 200 OK\r\n\r\n"),
            Err(FrameError::Malformed { .. })
        ));
    }

    #[test]
    fn a_method_this_relay_does_not_know_is_refused_rather_than_guessed() {
        assert!(matches!(
            request("BREW /x HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            Err(FrameError::Unsupported {
                detail: "unrecognised request method"
            })
        ));
    }

    #[test]
    fn header_names_and_connection_tokens_are_case_insensitive() {
        // A case-sensitive comparison here would be a disagreement with every
        // other parser, which is the thing this module refuses to do. The method
        // stays uppercase, and that is not an oversight — see the test below.
        let head = request("POST /x HTTP/1.1\r\ncOnTeNt-LeNgTh: 7\r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::Length(7));
        let head = response("HTTP/1.1 200 OK\r\nconnection: CLOSE\r\n\r\n").expect("framed");
        assert!(head.close_after);
    }

    #[test]
    fn a_method_is_case_sensitive_because_the_specification_says_so() {
        // `post` is not `POST`: HTTP methods are case-sensitive tokens, so
        // accepting a lowercase one would be this parser being *more* lenient
        // than the specification, and leniency about the request line is how a
        // component ends up disagreeing with one that is not.
        assert!(matches!(
            request("post /x HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            Err(FrameError::Unsupported {
                detail: "unrecognised request method"
            })
        ));
    }

    #[test]
    fn whitespace_around_a_header_value_is_stripped_because_it_must_be() {
        // The one leniency here, and it is not leniency: optional whitespace
        // around a field value is required to be removed, so a parser that kept
        // it would be the one out of step.
        let head = request("POST /x HTTP/1.1\r\nContent-Length:   7  \r\n\r\n").expect("framed");
        assert_eq!(head.framing, Framing::Length(7));
    }

    // --- what the relay has to notice beyond framing ------------------------

    /// The status is carried on the parsed head so the relay never has a second
    /// opinion about the bytes it is relaying.
    #[test]
    fn the_status_is_carried_by_the_head_that_was_framed() {
        assert_eq!(
            response("HTTP/1.1 204 No Content\r\n\r\n")
                .expect("framed")
                .status,
            Some(204)
        );
        assert_eq!(
            response("HTTP/1.1 100 Continue\r\n\r\n")
                .expect("framed")
                .status,
            Some(100)
        );
        // A request has no status, and saying so is what stops a caller from
        // reading `Some(...)` off a request and believing an origin answered.
        assert_eq!(
            request("GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n")
                .expect("framed")
                .status,
            None
        );
    }

    /// A `1xx` is not the end of the exchange. A relay that stopped reading on
    /// one would answer a client's `Expect: 100-continue` — and every other
    /// interim response — with a closed tunnel.
    #[test]
    fn an_interim_response_is_framed_as_a_head_with_no_body() {
        for status in [100u16, 102, 103] {
            let head = response(&format!("HTTP/1.1 {status} Interim\r\n\r\n")).expect("framed");
            assert_eq!(head.framing, Framing::None, "status {status}");
            assert_eq!(head.status, Some(status));
        }
    }

    /// The two shapes a sequential pump cannot be transparent to, detected.
    ///
    /// The control matters: a detector that never fires is indistinguishable
    /// from a detector that does not work, so the negative is asserted first and
    /// the positive is asserted against a head that differs only in the one
    /// header being looked for.
    #[test]
    fn a_plain_request_declares_neither_continue_nor_upgrade() {
        let head = b"GET /x HTTP/1.1\r\nHost: a.test\r\nConnection: keep-alive\r\n\r\n";
        assert!(!request_expects_continue(head));
        assert!(!request_declares_upgrade(head));
    }

    #[test]
    fn a_request_that_expects_continue_says_so() {
        let head = b"POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 4\r\n\
                    Expect: 100-continue\r\n\r\n";
        assert!(request_expects_continue(head));
        // And it is still framed, because the caller needs to know both things.
        let parsed = parse_request_head(head, 1024).expect("framed");
        assert_eq!(parsed.framing, Framing::Length(4));
        assert!(!request_declares_upgrade(head));
    }

    /// Case-insensitive, because a header name that is matched case-sensitively
    /// is a detector that fires on `expect` and not on `Expect`, which is the
    /// failure mode of every hand-written lookup in this codebase so far.
    #[test]
    fn the_declarations_are_found_whatever_their_spelling() {
        let lower = b"POST /x HTTP/1.1\r\nexpect: 100-CONTINUE\r\ncontent-length: 0\r\n\r\n";
        assert!(request_expects_continue(lower));
        let upgrade = b"GET /x HTTP/1.1\r\nUPGRADE: websocket\r\n\r\n";
        assert!(request_declares_upgrade(upgrade));
    }

    /// A head this parser refused entirely is not a head that declares anything.
    ///
    /// The control for both detectors above: a detector that answered `true` for
    /// input the framing parser has already rejected would have the relay refuse
    /// a request for the wrong stated reason.
    #[test]
    fn a_refused_head_declares_nothing() {
        let refused =
            b"POST /x HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(parse_request_head(refused, 1024).is_err());
        assert!(!request_expects_continue(refused));
        assert!(!request_declares_upgrade(refused));
    }
}
