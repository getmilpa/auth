# Changelog


## [0.3.10](https://github.com/getmilpa/auth/releases/tag/v0.3.10) (2026-08-12)

Accepts `milpa/command ^0.8`, which ships the descent field — an argument that lowers an operation's ceiling, with its reason carried in the declaration.

Widening only: no behaviour changes here. Capping the atom at `^0.7` is what stopped anything downstream from resolving a version that uses it; greenhouse `evidence/0151` measured eight packages holding that cap.

## [0.3.9](https://github.com/getmilpa/auth/compare/v0.3.8...v0.3.9) (2026-08-09)


### Bug Fixes

* **deps:** reach milpa/command ^0.7, where the ceiling grew a fifth dimension ([0d581ba](https://github.com/getmilpa/auth/commit/0d581bab02c5572cd2954f0436f6f99750b2bd89))

## [0.3.8](https://github.com/getmilpa/auth/compare/v0.3.7...v0.3.8) (2026-08-05)


### Bug Fixes

* **deps:** el rango de milpa/command admite 0.6 ([6bcb61a](https://github.com/getmilpa/auth/commit/6bcb61a836a95b5b07c8faf61f124f5891052e2a))

## [0.3.7](https://github.com/getmilpa/auth/compare/v0.3.6...v0.3.7) (2026-08-04)


### Bug Fixes

* **capability:** declara el contrato de cada id que provee ([f3e1aa1](https://github.com/getmilpa/auth/commit/f3e1aa17ad05546ffb0fd91021433f24e57eee9f))

## [0.3.6](https://github.com/getmilpa/auth/compare/v0.3.5...v0.3.6) (2026-08-04)


### Bug Fixes

* **composer:** declarar type milpa-capability para que el paquete sea descubrible por lo que es ([05206f7](https://github.com/getmilpa/auth/commit/05206f7165b2ad553050b34cb9f23601f2e404ae))

## [0.3.5](https://github.com/getmilpa/auth/compare/v0.3.4...v0.3.5) (2026-08-02)


### Bug Fixes

* widen milpa/command and milpa/plugin pins to accept the 0.5/0.8 minors ([7888444](https://github.com/getmilpa/auth/commit/788844452fee09cc6d179800a62b60fc4f47ed15))

## [0.3.4](https://github.com/getmilpa/auth/compare/v0.3.3...v0.3.4) (2026-08-01)


### Bug Fixes

* the capability contract speaks English ([e4e0270](https://github.com/getmilpa/auth/commit/e4e027046d32ab45cd38a518a47d860cd4b6aa87))

## [0.3.3](https://github.com/getmilpa/auth/compare/v0.3.2...v0.3.3) (2026-08-01)


### Bug Fixes

* este paquete declara que aporta ([16be2ca](https://github.com/getmilpa/auth/commit/16be2ca68fc417c20fb05e960451ed25c34f7aad))

## [0.3.2](https://github.com/getmilpa/auth/compare/v0.3.1...v0.3.2) (2026-08-01)


### Bug Fixes

* **deps:** el pin de milpa/command deja de ser una jaula de un minor ([49400b1](https://github.com/getmilpa/auth/commit/49400b14183d097ea8db2f2535aa903a680284d5))

## [0.3.1](https://github.com/getmilpa/auth/compare/v0.3.0...v0.3.1) (2026-07-31)


### Features

* AuthOperationHttpPolicy — deciding whether a caller may run an operation ([f24e7d0](https://github.com/getmilpa/auth/commit/f24e7d0d9d3c621ba665647aa7cb3a5dbaee43f5))

## [0.3.0](https://github.com/getmilpa/auth/compare/v0.2.0...v0.3.0) (2026-07-28)


### Miscellaneous Chores

* release 0.3.0 ([de4049d](https://github.com/getmilpa/auth/commit/de4049d28d7cf7ebbd2dca14129c1d08b74ab9ff))

## [0.2.0](https://github.com/getmilpa/auth/compare/v0.1.0...v0.2.0) (2026-07-14)


### Features

* permissions matrix (RBAC-lite) + passkey credential-type vocabulary ([344a632](https://github.com/getmilpa/auth/commit/344a63274d32fd9789043bde6348dbb7a8504c67))

## 0.1.0 (2026-07-14)


### Features

* the identity producer — Credential to Actor/AuthContext, PSR-15 middlewares, fail-closed scopes ([79d79bf](https://github.com/getmilpa/auth/commit/79d79bf32796bdffa691f1db0e7cb7a7441c958b))


### Miscellaneous Chores

* seed the version line at 0.1.0 ([53e0d67](https://github.com/getmilpa/auth/commit/53e0d679f1fcb287aa2e5d0bdbc952dfbfa42895))
