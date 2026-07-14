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
 * The kind of a {@see Credential}, or the ceremony that produced a session — the closed set the
 * framework recognises. A `Bearer` credential is the `Authorization: Bearer …` token; a `Cookie`
 * credential is the session-cookie value; `Passkey` marks a WebAuthn ceremony that mints a session
 * (a vocabulary marker for logs/UI/reports — NOT a per-request credential, and it never flows through
 * {@see Contracts\CredentialVerifier}). The set is deliberately closed, consistent with
 * {@see ActorType}: a credential's kind is identity, not a string a caller can invent.
 */
enum CredentialType: string
{
    case Bearer = 'bearer';
    case Cookie = 'cookie';
    case Passkey = 'passkey';
}
