# Correction — what the 0.3.0 release notes got wrong

The commit that cut `v0.3.0` (`de4049d`, 2026-07-28) claims that `v0.2.0` shipped without the
permissions matrix, and that Packagist had been serving an `auth 0.2.0` missing the feature its
release notes announced.

**That is false. `v0.2.0` contains the feature.** It always did.

## What is actually true

```bash
git ls-tree -r v0.1.0 --name-only | grep CatalogPermissionResolver   # nothing
git ls-tree -r v0.2.0 --name-only | grep CatalogPermissionResolver   # src/CatalogPermissionResolver.php

composer require milpa/auth:0.2.0
ls vendor/milpa/auth/src/CatalogPermissionResolver.php                # present
```

`v0.1.0` is the release that lacks it — correctly, since the feature landed after it.

## Where the wrong conclusion came from

`milpa/skeleton` pinned `milpa/auth: ^0.1`, which composer resolves to `0.1.x` and never to `0.2`.
Its tests failed with *Class CatalogPermissionResolver not found*, and that failure was real. The
diagnosis was not: the pin was stale, the tag was fine.

The probe that produced the false reading was `git show v0.2.0:src/CatalogPermissionResolver.php`,
which reported the file missing. That same probe reports the file missing for `v0.3.0` too — a
release that demonstrably contains it. So the probe failed for every input and its failure was read
as a finding.

The check that would have caught it costs one line: run the probe against a case known to be
positive before trusting it on an unknown one. It is the same discipline this project applies to
every gate it ships, and it was not applied here.

## What stands

One part of the original claim holds: the tag `v0.2.0` points at `93ab0b9`, a release commit that is
not an ancestor of `main` — an artifact of the release-please re-anchoring visible in the history
around it. That is untidy and it is not a missing feature; the tagged tree carries the same content.

`v0.3.0` itself is a legitimate release with real content. Only its stated justification was wrong,
and the wrong justification is what this file exists to contradict, since the commit message cannot
be rewritten without rewriting published history — the same reasoning applied elsewhere in this
family the same day.

Nothing needs to be reverted. If you pinned `^0.2` you have the permissions matrix; if you pinned
`^0.1` you never did, and that is the upgrade to make.
