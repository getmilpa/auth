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
 * The provenance of a grant: its {@see PermissionSourceType} and the id within it — a role id for
 * {@see PermissionSourceType::Role}, the raw scope string (including `'*'`) for
 * {@see PermissionSourceType::Scope}. This is what lets authorization be *explained*, not just decided.
 */
final readonly class PermissionSource
{
    public function __construct(
        public PermissionSourceType $type,
        public string $id,
    ) {
    }
}
