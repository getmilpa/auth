# Upgrading

## 0.11.0 — passkey ceremonies check the origin and user verification

*(This package is at v0.10.1; changing published signatures makes the next release a breaking one.)*

`WebAuthnAssertionVerifier` and `WebAuthnRegistrationVerifier` did not check the clientDataJSON
`origin` nor the authenticatorData UV (user verified) flag. A page on another origin that relayed the
ceremony to the real authenticator, or an authenticator that was touched but never verified its user,
was accepted. Every passkey login built on `PasskeyAuthenticator`/`PasskeyLogin` inherited that.

**What changed:**

| Before | After |
|---|---|
| `WebAuthnAssertionVerifier::verify($id, $pem, $challenge, string $rpId, …)` | `verify($id, $pem, $challenge, RelyingParty $rp, …)` |
| `WebAuthnRegistrationVerifier::verify($challenge, string $rpId, …)` | `verify($challenge, RelyingParty $rp, …)` |
| `PasskeyAuthenticator::authenticate(string $rpId, …)` | `authenticate(RelyingParty $rp, …)` |
| `PasskeyLogin::login(string $rpId, …)` | `login(RelyingParty $rp, …)` |
| no origin check | the origin must be one of `$rp->allowedOrigins` (exact string) |
| UV ignored | UV required unless the verifier is built with `UserVerificationRequirement::Preferred` or `::Discouraged` |
| `new RelyingParty(...)` accepted anything | throws `InvalidArgumentException` for an empty id, no origins, a non-`https` origin (plain `http` only on `localhost`/`127.0.0.1`/`[::1]`), an origin with a path or wildcard, or a host that is neither the id nor a subdomain of it |

**Fails closed, never open.** A caller still passing a string gets a `TypeError` naming the
`RelyingParty` parameter; there is no string overload that would skip the origin check. A
misconfigured `RelyingParty` throws where it is built, at boot.

**To migrate,** build the relying party where you read `rpId` today and pass it instead:

```php
// before
$login->login($rpId, $credentialId, $clientDataJson, $authenticatorData, $signature);

// after
$rp = new RelyingParty($rpId, 'My app', ['https://' . $rpId]);   // list every origin the page is served from
$login->login($rp, $credentialId, $clientDataJson, $authenticatorData, $signature);
```

Then make the browser ask for what the server now demands: `userVerification: 'required'` in both
`navigator.credentials.create()` and `.get()`. If your house admits authenticators without a PIN or
biometric on purpose, build the verifier with `UserVerificationRequirement::Preferred` and hand it to
`PasskeyAuthenticator` (third argument) or use it directly for registration.

Credentials already registered keep working: nothing stored changes, and the signature check is the
same. What stops working is an assertion that lacks UV or comes from an origin you did not list.

## 0.10.0 — the `Policy` seam is gone

*(This package is at v0.9.0; removing published classes makes the next release a breaking one.)*

`Milpa\Auth\Contracts\Policy`, `Milpa\Auth\PolicyDecision` and `Milpa\Auth\PolicyEffect` were **removed**.

They were a seam for attribute-based rules that this package deliberately does not have: `ADR 0002` decides
RBAC-lite and NOT ABAC. Measured across the framework's 37 packages before removing them, they had **zero
implementations and zero consumers** — the only code that named them was each other and one test of their own.

A published contract that nothing implements is not an extension point; it is a promise the code does not keep,
and an agent reading this package's surface counted it as a capability. Removing it is the honest half of the
decision ADR 0002 already took (greenhouse `decisions/0213` row 8, `decisions/0215`).

**If you implemented `Contracts\Policy`:** nothing consumed your implementation — no call site in this package
ever invoked a policy. Authorization here runs through `PermissionResolver`, `PermissionCatalog` and
`PermissionContext`, and that is where a host decision belongs today.

`PermissionSourceType::Policy` **stays**: it is a reserved provenance label on a grant, not part of the removed
seam, and a future policy grant can use it without a breaking change.
