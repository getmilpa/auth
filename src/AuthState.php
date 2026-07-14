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
 * The outcome of authenticating a request, carried by an {@see AuthContext}. `Anonymous` means no
 * credential was presented; `Authenticated` means one was presented and verified into an
 * {@see Actor}; `Invalid` means one was presented and rejected. The three are distinct on purpose —
 * "no credential" and "a bad credential" are different facts, and fail-closed policy must be able to
 * tell them apart rather than collapsing both into "not authenticated".
 */
enum AuthState: string
{
    case Anonymous = 'anonymous';
    case Authenticated = 'authenticated';
    case Invalid = 'invalid';
}
