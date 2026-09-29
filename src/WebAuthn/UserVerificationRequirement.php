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

namespace Milpa\Auth\WebAuthn;

/**
 * How strictly a ceremony demands user verification (the authenticatorData UV flag) — spelled as the
 * WebAuthn `userVerification` option the browser receives, so a host can send and verify the same value.
 *
 * `Required` is the verifiers' default: the UV flag proves the authenticator checked WHO is holding it
 * (PIN, biometric), not merely that someone touched it (UP). `Preferred` and `Discouraged` accept a
 * ceremony with presence alone; choose one of them only when the house deliberately admits authenticators
 * that cannot verify their user, and pass it to the verifier explicitly — it is never inferred.
 */
enum UserVerificationRequirement: string
{
    case Required = 'required';
    case Preferred = 'preferred';
    case Discouraged = 'discouraged';

    /** Whether a ceremony without the UV flag must be refused. */
    public function demandsVerification(): bool
    {
        return $this === self::Required;
    }
}
