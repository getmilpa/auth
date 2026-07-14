# Security Policy

## Supported Versions

Milpa Auth is pre-1.0. Only the latest `0.x` release line receives security fixes.

## Reporting a Vulnerability

Please report security vulnerabilities **privately** via GitHub Security Advisories
— the repository's **Security** tab → **Report a vulnerability** — rather than opening
a public issue or pull request.

We aim to acknowledge a report within 72 hours and to keep you informed as we work
on a fix. Once a fix is released, we will credit the reporter unless anonymity is
requested.

## Handling credentials

Milpa Auth is authorization infrastructure, so its own posture is part of your
attack surface. Two invariants are enforced by tests and must never regress:

- **`Credential` never leaks its value.** The raw token lives inside a closure, out
  of reach of `var_export()`, `print_r()`, `var_dump()`, `json_encode()`, and every
  exception message or stack trace. Only an explicit `value()` call returns it.
- **Fail-closed by construction.** An unknown scope, a null actor, or an unverified
  credential denies — never inherits a laxer policy. `hasScope()` matches exactly;
  the only wildcard is the explicit, documented `'*'`.

---

Milpa is developed and maintained by [TeamX Agency](https://teamx.agency).
