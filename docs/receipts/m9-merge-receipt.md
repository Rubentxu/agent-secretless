# M9 Merge Receipt

The local `main` checkout was pushed into `origin/main` via the SDDK release
capability `cap-git-push-5760c6138f1a` (`succeeded`), with
`--approve` supplied by the owner's release authorisation.

```
sddk release apply --tag v0.15.0 --root . --scope . \
  --cycle p-20a1ee316faf2ba3/m9-tls-acceptor --approve
converged: true
sha: 3f73a7979b7b84d5898a22b9bcad7d6503cb8a52
applied: 2
- git.push cap-git-push-5760c6138f1a
- git.tag  cap-git-tag-6b57d01d96db
```

## Preconditions at push

- behind `origin/main`: 0 commits
- ahead of `origin/main`: 5 commits (a 6th, the UAT plan and report, was
  committed first because the release precondition could not read them from
  XDG storage)
- worktree clean at push: yes

## Postconditions

| check | result |
|---|---|
| `git rev-parse HEAD` | `3f73a7979b7b84d5898a22b9bcad7d6503cb8a52` |
| `git rev-parse origin/main` | `3f73a7979b7b84d5898a22b9bcad7d6503cb8a52` |
| equal | yes |

## Commits pushed

| sha | summary |
|---|---|
| `e7ee75b` | feat(tls-acceptor): present a session leaf over a real TLS handshake |
| `1726686` | chore(release): bump to 0.15.0 |
| `17ef211` | test(tls-acceptor): verify the handshake with openssl, not only with rustls |
| `c4ac525` | test(tls-acceptor): make the chain-order assertion actually assert |
| `866476b` | test(tls-acceptor): cover REQ-6, which no test exercised |
| `3f73a79` | test(uat): v0.15.0 acceptance plan and report for the TLS acceptor |
