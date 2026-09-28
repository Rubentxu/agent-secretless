# Shell-First Agent Integration

## 1. Objective

The integration succeeds when the agent keeps behaving like a normal developer at a terminal.

The product must not require rewriting every prompt to say “call the secret MCP first”.

## 2. Launch model

```bash
asv run --profile auto -- jcode
```

or:

```bash
asv run --profile hardened -- codex
asv run -- my-custom-agent
```

The launcher:

1. asks broker to create a session,
2. sanitizes inherited secret-bearing environment variables,
3. establishes session UDS/listeners,
4. configures `SSH_AUTH_SOCK`,
5. prepends an ASV shim directory to `PATH`,
6. sets non-secret session refs/surrogates,
7. optionally installs proxy/session-CA environment,
8. places process into protected cgroup in hardened mode,
9. execs the agent.

## 3. Environment model

Allowed examples:

```bash
ASV_SESSION=019a...
ASV_SOCKET=/run/user/1000/asv/session.sock
SSH_AUTH_SOCK=/run/user/1000/asv/sessions/019a/ssh.sock
HTTPS_PROXY=http://127.0.0.1:43127      # when proxy mode enabled
GITHUB_TOKEN=__ASV_SURROGATE_GITHUB_7Q...__
```

The surrogate is not a remote credential. It is meaningful only to the local broker integration and is bound to the session.

Forbidden:

```bash
GITHUB_TOKEN=ghp_real...
AWS_SECRET_ACCESS_KEY=real...
```

## 4. Surrogate credentials

Some CLIs insist a credential exists before they make a request. ASV may create a **surrogate** value that satisfies local syntax but has no provider-side authority.

Properties:

- random/session-scoped,
- maps to a credential ID only inside broker state,
- audience-bound,
- expires with session,
- never accepted by external provider,
- recognizable by broker after TLS termination or protocol parsing,
- safe to leak in logs from an authentication standpoint, though still redacted to avoid topology disclosure.

For tools with strict format validation, connector-specific surrogate generators may produce values matching expected shape. They must be unmistakably non-production internally and collision-resistant.

## 5. PATH shims

Location:

```text
/run/user/$UID/asv/sessions/$SESSION/bin/
```

A shim is permitted only when it improves compatibility. It is not a security authority.

Responsibilities:

- discover session,
- choose integration strategy,
- possibly rewrite a safe endpoint flag,
- execute the real binary,
- preserve exit code/signals/TTY.

Shims MUST NOT contain or retrieve raw secrets.

Example:

```text
aws shim
  -> ensure requests target local signing/proxy endpoint where supported
  -> exec real aws
```

## 6. Integration strategy selector

For each tool/service pair:

```text
NATIVE_SIGNER
PROTOCOL_PROXY
SERVICE_REVERSE_PROXY
EXPLICIT_HTTP_PROXY
TRANSPARENT_EBPF_PROXY
SHORT_LIVED_TOKEN
ISOLATED_EXEC
UNSUPPORTED
```

`asv doctor` detects installed binaries and reports the strongest supported strategy.

## 7. Shell support

MVP:

- POSIX sh
- bash
- zsh

Next:

- fish
- nushell

`shell-init` installs completions and convenience functions only; it does not export real credentials.

## 8. Secret environment quarantine

Before launching an agent, scan variable **names**, not values, against:

- built-in provider catalog,
- suffix/prefix patterns (`TOKEN`, `SECRET`, `PASSWORD`, `API_KEY`, etc.),
- user-defined sensitive names.

Modes:

```text
strict      strip all detected variables; default for hardened sessions
prompt      human decides before launch
permissive  retain; session is visibly marked degraded
```

Never print the value during diagnosis.

## 9. CLI ingestion safety

Never:

```bash
asv credential add --secret SUPERSECRET
```

Allow:

```bash
asv credential add github
# native no-echo prompt
```

or descriptor-based input from a trusted helper:

```text
Tauri -> secure ingest helper -> broker UDS
```

## 10. Command compatibility contract

A shim/proxy must preserve:

- stdin/stdout/stderr,
- TTY behavior,
- signals,
- exit code,
- working directory,
- expected config paths,
- non-secret environment,
- latency low enough to be invisible in normal use.

## 11. “Agent barely notices” success criteria

For supported integrations, an agent should be able to run ordinary commands without:

- requesting/copying a token,
- editing a secret file,
- injecting a raw environment variable,
- pasting secrets in prompts,
- learning provider-specific secret retrieval flows.
