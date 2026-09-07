# Upgrading

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
