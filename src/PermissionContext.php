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
 * What a request is scoped to — never who the actor is. The resolver reads identity from the
 * {@see Actor} and scoping from here; the two are deliberately not mixed. Immutable by construction.
 */
final readonly class PermissionContext
{
    public function __construct(
        public ?string $tenantId = null,
        public ?string $resourceType = null,
        public ?string $resourceId = null,
    ) {
    }

    /** The empty context — no tenant, no resource. */
    public static function none(): self
    {
        return new self();
    }
}
