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

/**
 * The 403 signal that a request authenticated fine but is not *allowed* here — it holds none of the
 * scopes the route requires. Distinct from the 401s on purpose: the caller is known, they simply lack
 * permission, and re-authenticating will not help. The message names the required scopes (the
 * developer's own policy, never a secret) so the fix is obvious: grant the actor one of them, or guard
 * the route with a scope the actor already holds.
 */
final class ScopeDeniedException extends AuthException
{
    /**
     * Builds the denial for a route that required one of `$required` and the actor held none of them.
     *
     * @param list<string> $required the scopes any one of which would have satisfied the guard
     */
    public static function forRequiredScopes(array $required): self
    {
        $scopes = $required === [] ? '(none configured — this guard denies every actor)' : implode(', ', $required);

        return new self(
            '[MILPA_SCOPE_DENIED] This request authenticated but is not allowed here: it holds none of '
            . 'the required scope(s): ' . $scopes . '. Grant the actor one of those scopes, or guard the '
            . 'route with a scope the actor already holds. Why Milpa authorizes on explicit scopes: '
            . self::ACADEMY_LINK,
            403,
            'MILPA_SCOPE_DENIED',
        );
    }
}
