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

/** The three outcomes a {@see Contracts\Policy} may return. Future rule: deny-override — any Deny wins; Abstain defers to RBAC. */
enum PolicyEffect: string
{
    case Allow = 'allow';
    case Deny = 'deny';
    case Abstain = 'abstain';
}
