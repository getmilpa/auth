<?php

/**
 * This file is part of Milpa Auth — the runtime-native identity vocabulary of the Milpa PHP framework.
 *
 * (c) Rodrigo Vicente - TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/auth
 */

declare(strict_types=1);

namespace Milpa\Auth;

/**
 * An opaque wrapper around a raw secret (a bearer token, a session cookie value, …) plus its
 * {@see self::$type}. Its whole reason to exist is that the raw value MUST NOT leak: it is the one
 * thing in the system that, printed to a log or an error, hands an attacker the keys.
 *
 * It uses the idiomatic modern-PHP shape for a secret-bearing value object: the value is a
 * `private readonly` property marked `#[\SensitiveParameter]` at construction (so it is redacted from
 * stack-trace argument dumps), {@see self::__debugInfo()} redacts it (so `print_r`/`var_dump` render
 * `['type' => …, 'value' => '[redacted]']`), both {@see self::__serialize()} and {@see self::__clone()} refuse outright (a secret
 * must never survive serialization — a record rebuilt with `'[redacted]'` would be a silent bomb, so
 * we fail loudly instead). There is deliberately NO `__toString()`: casting a Credential to a string
 * is a bug, and must raise an Error rather than quietly hand back — or leak — the secret. The one
 * deliberate exit is {@see self::value()}, for the verifier that actually has to check the secret.
 * Treat any other appearance of the raw value as a security bug.
 */
final class Credential
{
    public function __construct(
        #[\SensitiveParameter]
        private readonly string $value,
        public readonly CredentialType $type,
    ) {
    }

    /**
     * A bearer-token credential — the `Authorization: Bearer …` case.
     */
    public static function bearer(#[\SensitiveParameter] string $value): self
    {
        return new self($value, CredentialType::Bearer);
    }

    /**
     * A cookie credential — the session-cookie case.
     */
    public static function cookie(#[\SensitiveParameter] string $value): self
    {
        return new self($value, CredentialType::Cookie);
    }

    public function value(): string
    {
        return $this->value;
    }

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['type' => $this->type->value, 'value' => '[redacted]'];
    }

    /**
     * @return array<string, never>
     *
     * @throws \LogicException always
     */
    public function __serialize(): array
    {
        throw new \LogicException('Credential must not be serialized — it carries a secret; persist a SessionRecord instead.');
    }

    public function __clone(): void
    {
        throw new \LogicException('Credential must not be cloned — it carries a secret.');
    }
}
