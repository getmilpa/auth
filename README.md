<p align="center">
  <a href="https://github.com/getmilpa">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-dark.svg">
      <img src="https://raw.githubusercontent.com/getmilpa/core/main/art/lockup/milpa-lockup-v-color-light.svg" alt="Milpa" width="300">
    </picture>
  </a>
</p>

# Milpa Auth

> Runtime-native **identity vocabulary** for Milpa: the typed `Actor` / `AuthContext` / `AuthState` primitives, an opaque `Credential` that never leaks its value, and the `CredentialVerifier`, `AuthContextFactory` and `SessionStore` contracts. The trusted producer of the context policies need — fail-closed by construction, zero framework, zero ORM.

[![CI](https://github.com/getmilpa/auth/actions/workflows/ci.yml/badge.svg)](https://github.com/getmilpa/auth/actions/workflows/ci.yml)
[![Packagist](https://img.shields.io/packagist/v/milpa/auth.svg)](https://packagist.org/packages/milpa/auth)
[![PHP](https://img.shields.io/badge/php-%E2%89%A5%208.3-777bb4.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-API%20reference-blue.svg)](https://getmilpa.github.io/auth/)

**Auth is not login. Auth is the trusted producer of the context policies need to stop lying.**

Authorization has three moving parts. A **carrier** holds a request's identity and scopes; an
**enforcer** decides whether that identity may do the thing. Milpa already has both. What was
missing is the **producer**: the piece that verifies a credential and *builds* a trusted identity
in the first place. Without it, every transport asserts its own identity — a CLI hands out a
wildcard, an HTTP route trusts a header it never checked — and the enforcer is authorizing against
a context nobody verified.

`milpa/auth` is that producer's foundation: the typed vocabulary of identity, and the contracts a
verifier and a session store implement. It defines **what** authorization needs to know about a
caller — and nothing about **how** you store it.

## Install

```bash
composer require milpa/auth
```

## The shape

Five types and three contracts, no more:

```php
use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\AuthContext;
use Milpa\Auth\Credential;

// An Actor is a verified identity: who is acting, and what they may do.
$actor = new Actor(
    id: 'u-42',
    type: ActorType::User,          // User | Agent | Service — a closed set, because it is identity
    scopes: ['posts:read', 'posts:write'],
    claims: ['email' => 'ada@example.com'],
);

// An AuthContext is the trusted answer to "who is this, and may we trust it?"
$ctx = AuthContext::authenticated($actor);

$ctx->isAuthenticated();          // true
$ctx->hasScope('posts:read');     // true
$ctx->hasScope('posts:delete');   // false — fail-closed, an absent scope is denied
$ctx->hasAnyScope(['a', 'b']);    // false

// No credential? An anonymous context — distinct from a *rejected* one.
AuthContext::anonymous()->isAuthenticated();   // false
AuthContext::anonymous()->hasScope('*');       // false — no actor, so nothing is granted

// A bad credential? An invalid context, with the reason recorded — not the same as anonymous.
AuthContext::invalid('expired token')->state;  // AuthState::Invalid
```

### Fail-closed, and the one explicit wildcard

`hasScope()` is an **exact string match**. A scope you do not hold is denied — there is no prefix,
suffix, or glob magic. The single exception is the literal `'*'`, a **documented** wildcard for a
superuser or a trusted process:

```php
$agent = new Actor('bot-1', ActorType::Agent, scopes: ['*']);
$agent->hasScope('anything-at-all');   // true — '*' is the one explicit escape hatch

$scoped = new Actor('u-1', ActorType::User, scopes: ['posts:*']);
$scoped->hasScope('posts:read');       // false — 'posts:*' is NOT a wildcard, only bare '*' is
```

There is no magic wildcard. If a caller can do something, it is because a scope says so — exactly,
or via the one `'*'` you granted on purpose.

### A `Credential` never leaks its value

A `Credential` is an opaque wrapper around a raw secret — the one thing that, printed to a log or an
error, hands an attacker the keys. It uses the idiomatic modern-PHP shape for a secret-bearing value
object: the value is a `private readonly` property marked `#[\SensitiveParameter]` (redacted from
stack-trace argument dumps), `__debugInfo()` redacts it (so `print_r`/`var_dump` show `[redacted]`),
`__serialize()` and `__clone()` refuse outright (a secret must never survive serialization nor be
silently duplicated — both throw), and there is deliberately no `__toString()` (casting a Credential
to a string is a bug and raises an `Error`).

```php
$cred = Credential::bearer('the-real-token');

print_r($cred);              // ['type' => 'bearer', 'value' => '[redacted]']
json_encode($cred);          // {"type":"bearer"}  — the value is private, never serialised
serialize($cred);            // throws LogicException — a Credential must never be persisted
clone $cred;                 // throws LogicException — a Credential must never be duplicated
(string) $cred;              // Error — no __toString; a Credential is not a string

$cred->value();              // "the-real-token" — the one deliberate way out, for the verifier
```

Only an explicit `value()` call returns the secret. Treat any other appearance of it as a bug.

Two casual-dump surfaces — `var_export()` and the `(array)` cast — read an object's raw private
properties directly and bypass `__debugInfo()`, so they *do* surface the value. Sealing them would
require holding the secret outside the object (a closure or a `WeakMap`); Milpa deliberately keeps the
plain, readable idiom instead, and the rule is simply: never `var_export()` or `(array)`-cast a
Credential. The high-probability logging paths (`print_r`, `var_dump`, `json_encode`, exception
messages and traces) are all sealed, and `serialize()` — the highest-risk persistence path — throws.

## Auth defines *what* it needs; storage decides *how*

The producer's job is to turn a credential into an `AuthContext`. It should never own a database.
So `milpa/auth` ships **contracts**, not backends:

| Contract | Its one job |
|---|---|
| `CredentialVerifier` | `verify(Credential): AuthContext` — the producer itself: prove a credential, or reject it fail-closed. |
| `AuthContextFactory` | `fromRequest(ServerRequestInterface): AuthContext` — the HTTP entry point a middleware calls once per request. |
| `SessionStore` | `read` / `write` / `destroy` opaque, revocable, expiring sessions — **what** auth needs from storage, not how. |

A `SessionRecord` is the plain, storage-agnostic shape a `SessionStore` moves: who the session
belongs to, what it grants, when it expires, whether it was revoked. It knows how to decide its own
validity, and how to project itself back into an `Actor` — but nothing about where it is kept:

```php
use Milpa\Auth\SessionRecord;

$record->isValid($now);   // false if expired as of $now, or revoked — fail-closed
$record->toActor();       // the live Actor the enforcer authorizes against
```

Because storage is a contract, a downstream package chooses the medium — a
[`milpa/data`](https://github.com/getmilpa/data) backend, Redis, a database table — while `milpa/auth`
stays a near-leaf primitive that reaches for none of them. **Auth defines what it needs from storage;
data decides how.**

### The in-memory store, for tests and zero-file consumers

`InMemorySessionStore` is the reference `SessionStore`: an array kept in process memory, nothing
written to disk. It is **fail-closed on read** — an absent, expired, or revoked session all read as
`null`, so a stale session can never resurrect an actor. Expiry is evaluated against an **injectable
clock**, never the ambient wall clock, so time is deterministic and testable:

```php
use Milpa\Auth\InMemorySessionStore;

$store = new InMemorySessionStore(fn () => new DateTimeImmutable('2026-01-01 00:00:00'));
$store->write($record);
$store->read($record->id);   // the record — or null if it is expired/revoked as of the clock
```

## Requirements

- PHP **≥ 8.3**
- `psr/http-message` and `psr/http-server-middleware` (the PSR interfaces the HTTP seam speaks)
- Nothing else — `milpa/auth` has no `milpa/*` runtime dependency, no ORM, no framework

## Documentation

**Full API reference: [getmilpa.github.io/auth](https://getmilpa.github.io/auth/)** —
generated straight from the source DocBlocks and dressed with the Milpa design system.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Please report security
issues via [SECURITY.md](SECURITY.md), and note that this project follows a
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE) © Rodrigo Vicente - TeamX Agency.

---

Milpa is designed, built, and maintained by **[Rodrigo Vicente - TeamX Agency](https://teamx.agency/?utm_source=github&utm_medium=readme&utm_campaign=milpa&utm_content=auth)**.
