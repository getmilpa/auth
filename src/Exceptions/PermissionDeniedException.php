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

namespace Milpa\Auth\Exceptions;

use Milpa\Auth\Permission;

/**
 * The 403 signal that a request authenticated fine but is not *allowed* here — it does not hold the
 * required {@see Permission}. Sibling of {@see ScopeDeniedException} (same {@see AuthException} base,
 * same 403 shape) so error contracts do not move. The message names the required permission key (the
 * developer's own policy, never a secret) and links the concept.
 */
final class PermissionDeniedException extends AuthException
{
    /**
     * Builds the denial for a route that required `$required` and the actor did not hold it.
     */
    public static function forRequired(Permission $required): self
    {
        return new self(
            '[MILPA_PERMISSION_DENIED] This request authenticated but is not allowed here: it does not '
            . 'hold the required permission "' . $required->key() . '". Grant the actor a role that includes '
            . 'it, or guard the route with a permission the actor already holds. Why Milpa authorizes on '
            . 'explicit permissions: ' . self::ACADEMY_LINK,
            403,
            'MILPA_PERMISSION_DENIED',
        );
    }
}
