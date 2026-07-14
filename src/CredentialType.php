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
 * How a {@see Credential} arrived — the closed set of transports the framework recognises. A `Bearer`
 * credential is the `Authorization: Bearer …` token; a `Cookie` credential is the session-cookie
 * value. The set is deliberately closed (a vocabulary, not free-form metadata), consistent with
 * {@see ActorType}: a credential's kind is identity, not a string a caller can invent.
 */
enum CredentialType: string
{
    case Bearer = 'bearer';
    case Cookie = 'cookie';
}
