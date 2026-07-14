# Contributing to Milpa Auth

Thanks for your interest in contributing! Milpa Auth is the runtime-native identity
vocabulary of the Milpa framework — the typed `Actor` / `AuthContext` / `AuthState`
primitives, an opaque `Credential`, and the `CredentialVerifier`, `AuthContextFactory`
and `SessionStore` contracts. It is a near-leaf primitive: it depends only on PHP and
the PSR HTTP message / server-middleware interfaces.

## Getting started

```bash
composer install
vendor/bin/phpunit
vendor/bin/phpstan analyse src
php tools/validate-docblocks.php
```

These run in CI on PHP 8.3 and 8.4 (alongside `composer validate --strict` and a
`php -l` syntax pass); run them locally before opening a PR.

## Guidelines

- **PHP >= 8.3**, with `declare(strict_types=1);` in every file.
- **Document every public symbol.** A public class/interface/enum/trait or public
  method without a DocBlock summary fails CI (`tools/validate-docblocks.php`).
  Trivial accessors and magic methods are exempt.
- **Fail-closed always.** Auth is where "correct by construction" is paid for or lost.
  An unknown scope, an absent actor, or an unverified credential must **deny** — never
  inherit a laxer policy. The only wildcard is the explicit `'*'`; there is no magic.
- **No credential ever reaches a log, error, or dump.** `Credential` keeps its raw
  value in a closure so `var_export()`, `print_r()`, `var_dump()` and exceptions can
  only ever print `Credential(kind, [redacted])`. A change that would let the value
  surface anywhere but an explicit `value()` call is a security regression, not a PR.
- **Respect the tier boundary.** Milpa Auth is a near-leaf primitive: PHP plus the PSR
  HTTP interfaces, nothing else. No `milpa/core` at runtime, no ORM, no framework. It
  defines *what* auth needs (the `SessionStore` contract); a downstream package decides
  *how* to store it. A change that would pull in a runtime dependency belongs elsewhere.
- **[Conventional Commits](https://www.conventionalcommits.org/)** — releases and
  the CHANGELOG are generated automatically from commit messages. Use
  `feat:` / `fix:` / `docs:` / `chore:` etc.; a breaking change to a public
  interface or capability schema is a `feat!:` / `BREAKING CHANGE:` (bumps MINOR
  while the package is `0.x`, MAJOR once it reaches `1.0`).

## Code style

The whole Milpa family (`milpa/core`, `milpa/http`, `milpa/tool-runtime`,
`milpa/data`, `milpa/auth`) shares one coding standard, committed verbatim in
every repo as `.php-cs-fixer.dist.php` and enforced by CI. In short:

- **[PSR-12](https://www.php-fig.org/psr/psr-12/) base**: 4 spaces (never tabs);
  opening braces on the **next line** for classes and methods, on the **same line**
  for control structures; one statement per line.
- **Family deltas on top of PSR-12**: short array syntax (`[]`), one space around
  string concatenation (`$a . $b`), fully-multiline method arguments when split,
  no unused imports, aligned/separated/trimmed PHPDoc tags, trailing commas in
  multiline constructs.

Check and fix locally before pushing:

```bash
vendor/bin/php-cs-fixer fix --dry-run --diff   # what CI runs
vendor/bin/php-cs-fixer fix                    # apply
```

Do not tweak `.php-cs-fixer.dist.php` in one package alone — the standard changes
in lockstep across the family or not at all.

## Pull requests

Keep PRs focused, add tests for behavior changes, and make sure the four commands
above are green. A maintainer will review and, once merged to `main`,
release-please will handle versioning.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).

---

Milpa is developed and maintained by [TeamX Agency](https://teamx.agency).
