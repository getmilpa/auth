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
 * A {@see Permission} together with the {@see PermissionSource} that granted it — the unit a
 * {@see PermissionSet} holds so it can answer "what can this actor do, and why?".
 */
final readonly class GrantedPermission
{
    public function __construct(
        public Permission $permission,
        public PermissionSource $source,
    ) {
    }
}
