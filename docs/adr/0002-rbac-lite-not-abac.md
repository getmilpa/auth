# ADR 0002 — RBAC-lite, not ABAC

**Status:** Accepted (Rod, 2026-07-14)
**Context:** `milpa/auth` rebanada 2a — the permissions matrix. Scopes (rebanada 1) answer "what
string does this identity hold?"; the product asks a richer question: "may {actor} {action}
{resource}, and why?" That needs roles, a catalog to expand them against, and a resolved result
that can explain itself. The open question was how far to take it — full attribute-based access
control (ABAC), with conditions over actor/resource/context attributes evaluated by a rule engine,
or a narrower, structured role model that stays inspectable.

## Decision

Ship **structured RBAC-lite** — `Permission` (the canonical `{namespace}.{resource}:{action}` key),
`Role` (a named bundle of `Permission`s), `PermissionSet` (the resolved grants, each carrying a
`PermissionSource`), and a `PermissionResolver` contract with one reference implementation,
`CatalogPermissionResolver`. Do **NOT** build a general ABAC engine in this package.

The `Policy` interface (`allows(Actor, Permission, PermissionContext): PolicyDecision`) is defined
as the seam a future ABAC layer plugs into — the intended composition is **deny-override** (any
`Policy::Deny` wins over RBAC; `Abstain` defers to it). 2a ships this interface, `PolicyDecision`,
and `PolicyEffect` with **zero implementations and zero registration** — nothing consults a `Policy`
unless a host wires one in.

The reference resolver, `CatalogPermissionResolver`, is **intentionally tenant-blind**: it threads
`PermissionContext` (which carries `$tenantId`) through `resolve()` without reading it. Tenant
membership is product policy, not auth vocabulary — a host that needs "role X only inside tenant Y"
supplies its own `PermissionResolver`, or a `Policy`, rather than this leaf guessing at tenant
conventions it cannot know.

`'*'` remains the only wildcard, exactly as it is for scopes (ADR-adjacent to rebanada 1): a role's
permission list is a flat set of exact keys, never a glob. And the model is **total-backward-compatible**
with flat scopes — an actor with no roles and no resolved `PermissionSet` still answers correctly
through `AuthContext::can()`'s flat-scope fallback, so `can('posts', 'read') ≡ hasScope('posts:read')`
for every pre-2a caller.

## Rationale

An ABAC engine (arbitrary conditions over actor claims, resource attributes, and request context,
evaluated by a general rule interpreter) is a different, much larger contract: it needs a rule
language, an evaluation order, and a way to explain a decision that depends on data the auth layer
was never meant to own. Building that now would mean guessing at a shape no real host has asked
for yet, and it would make every permission check as hard to audit as the rule engine that produced
it.

RBAC-lite is the smaller, honest commitment: a permission is either granted — by a role or by a
flat scope — or it is not, and `PermissionSet::sourcesOf()` can always name which. That is what
authorization needs to be *explainable*, which matters more at this stage than being maximally
expressive. The `Policy` seam exists precisely so that when a real ABAC need shows up (a condition
an enumerated role genuinely cannot express), it lands as an addition — a class implementing
`Policy` — not a breaking change to `Permission`, `Role`, or `PermissionResolver`.

Tenant-blindness follows the same discipline as the rest of `milpa/auth`: this package defines
*what* authorization needs to know, never *how* a specific product's multi-tenancy works. A tenant
model is a decision every host makes differently (single-tenant, shared-schema, siloed) — baking
one into the default resolver would make it wrong for most of them.

## Policy (the RBAC-lite contract)

1. `Permission`, `Role`, `PermissionSet`, `GrantedPermission`, and `PermissionSource` are the closed
   vocabulary of 2a. No implicit hierarchy, no attribute conditions, no glob matching beyond the
   single literal `'*'`.
2. `PermissionResolver` is the one extension point for *how* roles and scopes become grants.
   `CatalogPermissionResolver` is the shipped reference; a host MAY supply its own (e.g.
   tenant-aware) resolver behind the same contract.
3. `Policy` / `PolicyDecision` / `PolicyEffect` are defined but **unimplemented** in 2a. A future
   ABAC extension composes as deny-override: a `Policy::Deny` overrides an RBAC allow;
   `Policy::Abstain` defers to the `PermissionSet`. This package does not commit to *when* that
   ships, only to the shape it will take.
4. The default `CatalogPermissionResolver` MUST NOT read `PermissionContext::$tenantId`. Tenant
   membership is product policy, not auth vocabulary — encoding it here would make the resolver
   wrong for every host whose tenancy model differs.
5. `'*'` is the only wildcard, for permissions exactly as for scopes. A role's `permissions` list is
   a flat set of exact `Permission` keys — never a prefix or glob.
6. `AuthContext::can()` MUST fall back to the flat-scope check when no `PermissionSet` is attached,
   so every pre-2a caller keeps working with no migration: `can('posts', 'read') ≡
   hasScope('posts:read')`.
7. Every grant a resolver produces MUST carry a `PermissionSource` naming where it came from (a role
   id or a scope string) — an authorization result that cannot name its own provenance is not
   considered resolved.

**Decision phrase:** *Si no podés explicar de dónde salió un permiso, todavía no tenés autorización
madura.*

---

[Apache-2.0](LICENSE) © Rodrigo Vicente - TeamX Agency.
