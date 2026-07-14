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
 * What kind of thing an {@see Actor} is — the closed set of identity classes the framework
 * recognises. A `User` is a human, an `Agent` is an autonomous AI actor acting on someone's
 * behalf, a `Service` is a machine-to-machine caller. The set is deliberately closed: it is
 * identity, not free-form metadata, and every audited action can name which of the three took it.
 */
enum ActorType: string
{
    case User = 'user';
    case Agent = 'agent';
    case Service = 'service';
}
