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

namespace Milpa\Auth\Contracts;

use Milpa\Auth\AuthContext;
use Milpa\Auth\Credential;

/**
 * The producer: turns a raw {@see Credential} into a trusted {@see AuthContext}. This is the seam
 * the whole package is built around — every way of proving identity (a session store, an OAuth
 * provider, an API-key table) is one implementation of this one method. It must be fail-closed: an
 * unrecognised or rejected credential returns {@see AuthContext::invalid()}, never a laxer context,
 * and the raw value never reaches a log or an error on the way.
 */
interface CredentialVerifier
{
    /**
     * Verifies `$credential` and produces the {@see AuthContext} it proves — authenticated on
     * success, {@see AuthContext::invalid()} when the credential is rejected. Never throws the raw
     * credential value into an error.
     */
    public function verify(Credential $credential): AuthContext;
}
