# ADR 0001 — Secret-bearing value objects

**Status:** Accepted (Rod, 2026-07-14)
**Context:** `milpa/auth` rebanada 1 — `Credential` is the first of a family of secret-bearing types (`ApiToken`, `ClientSecret`, `RefreshToken`, `CsrfToken`, `WebhookSecret`, …). How they hold and hide their secret must be ONE idiom, decided empirically against real leak vectors, not by taste.

## Decision

Use **idiomatic secret-bearing value objects** with explicit redaction and refusal semantics. **Do NOT use Closure/WeakMap indirection** for `Credential` (or any secret-bearing type).

The secret lives in a plain `private readonly string` marked `#[\SensitiveParameter]`. Access is only through an explicit `value()` method. There is no `__toString()`. `__debugInfo()` is always redacted. `__serialize()` and `__clone()` refuse outright (throw). `json_encode` exposes nothing (the secret is a private property).

## Rationale

`var_export()` and `(array)`-cast leaks are **PHP-level residuals** when a secret is stored as an object property: those functions read raw private properties and bypass `__debugInfo()`. Sealing them requires hiding the value **outside** the object (a `\Closure` or `\WeakMap` vault), which makes the value object semantically unusual — it no longer *has* a value, it has a function that returns one — and propagates a magic idiom across the entire secret-bearing family. Milpa does not use magic to fake perfect security; it relies on explicit contracts, visible boundaries, and honest errors.

The empirical matrix (PHP 8.3, `zend.exception_ignore_args` 0 and 1): the idiom seals **9 of 11 vectors** — `print_r`, `var_dump`, `get_object_vars` (external scope), `json_encode`, `serialize` (throws), `clone` (throws), `(string)` (Error), and stack-trace arg dumps (`#[\SensitiveParameter]`, **independent of env config**). The two residuals are `var_export()` and `(array)` cast.

## Policy (the Secret-bearing object contract)

`var_export()` and `(array)`-cast are **forbidden operations** for secret-bearing objects. Their leakage is **pinned by characterization tests** and documented as an explicit boundary — **never falsely marked "safe."**

Every secret-bearing type MUST:
1. keep the secret in a `private` property;
2. expose it only through an explicit `value()`;
3. have NO `__toString()`;
4. redact `__debugInfo()`;
5. refuse `__serialize()` explicitly (throw);
6. refuse `clone` explicitly (throw);
7. mark the secret arg `#[\SensitiveParameter]` (constructors, factories, verifier args);
8. never expose the secret through `json_encode`;
9. treat `var_export()` and `(array)` cast as forbidden by contract;
10. pin the residual leaks with characterization tests, not maquillaje.

**Decision phrase:** *No vamos a deformar el modelo para proteger operaciones que el contrato prohíbe.*
