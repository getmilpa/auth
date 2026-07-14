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
use Milpa\Auth\PermissionContext;
use Milpa\Auth\PermissionSet;

/**
 * Turns an identity + a request context into an inspectable decision: expand the actor's roles and
 * lift its flat scopes into a {@see PermissionSet}, attaching provenance. Runs once per request. The
 * reference implementation ({@see \Milpa\Auth\CatalogPermissionResolver}) is deliberately tenant-blind;
 * a tenant-aware host swaps in its own — tenant membership is product policy, not auth vocabulary.
 */
interface PermissionResolver
{
    /**
     * Resolves $actor's roles and scopes into a {@see PermissionSet}, scoped by $context.
     */
    public function resolve(Actor $actor, PermissionContext $context): PermissionSet;
}
