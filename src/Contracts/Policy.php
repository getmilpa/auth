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

use Milpa\Auth\Actor;
use Milpa\Auth\Permission;
use Milpa\Auth\PermissionContext;
use Milpa\Auth\PolicyDecision;

/**
 * The optional post-RBAC hook. 2a defines this seam and ships NO implementation and NO registration —
 * nothing consults a policy unless a host wires one. It is the extension point that lets attribute-based
 * rules (ABAC) land later with no breaking change; the intended composition is deny-override.
 */
interface Policy
{
    /** Check if an actor is allowed to perform an action on a resource in the given context. */
    public function allows(Actor $actor, Permission $permission, PermissionContext $context): PolicyDecision;
}
