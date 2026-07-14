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
 * Where a granted permission came from. 2a emits only {@see self::Role} and {@see self::Scope};
 * {@see self::Policy} and {@see self::System} are reserved so a future policy/system grant needs no
 * schema change.
 */
enum PermissionSourceType: string
{
    case Role = 'role';
    case Scope = 'scope';
    case Policy = 'policy';
    case System = 'system';
}
