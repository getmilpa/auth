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
 * The 500 that draws Rod's binding architectural line: an operation declared `scopes`, but the host
 * never wired the auth chain that could enforce them (no `CredentialVerifier` / `AuthContextFactory`
 * resolvable in the container, so nothing produces the {@see \Milpa\Auth\AuthContext} a scope guard
 * reads). This is a HOST CONFIGURATION error, not a request outcome — so it is deliberately NOT a 401
 * or 403. A 401 ({@see AuthContextMissingException}) or 403 ({@see ScopeDeniedException}) would blame
 * the caller, implying they could fix it by authenticating or by holding a scope; but the caller did
 * nothing wrong — the SERVER declared a protected operation and left it unguarded. Surfacing that as a
 * 5xx keeps the meaning honest: fail closed (the operation never runs unguarded) AND fail loud (the
 * misconfiguration is the server's to fix). It never names a credential; there is none to name.
 */
final class AuthMiddlewareNotInstalledException extends AuthException
{
    /**
     * The Academy case that walks the exact hole this closes: HTTP declaring `$op->scopes` yet running
     * the atom unguarded. May 404 until the case ships; the link is the durable target.
     */
    public const ACADEMY_CASE_LINK = 'https://academy.milpa.lat/artifacts/atomo?case=http-scope-hole';

    /**
     * Builds the misconfiguration error for an operation that declared `$scopes` on a surface whose
     * host installed no auth chain to enforce them.
     *
     * @param string       $operation the operation whose declared scopes cannot be enforced
     * @param list<string> $scopes    the scopes it declared — the host's own policy, never a secret
     */
    public static function forScopedOperation(string $operation, array $scopes): self
    {
        $declared = $scopes === [] ? '(none)' : implode(', ', $scopes);

        return new self(
            '[MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED] Operation \'' . $operation . '\' declares scope(s): '
            . $declared . ', but this host installed no auth chain to enforce them — nothing resolvable '
            . 'in the container produces an AuthContext (no CredentialVerifier / AuthContextFactory). '
            . 'This is a SERVER configuration error, not a failed request: it is deliberately a 500, not '
            . 'a 401/403, because the caller did nothing wrong — the host declared a protected operation '
            . 'and left it unguarded. Fix it on the host: wire a CredentialVerifier (and run '
            . 'AuthenticateMiddleware/StartSession) so a verified context reaches the scope guard. The '
            . 'hole this closes: ' . self::ACADEMY_CASE_LINK . ' — why Milpa fails closed: ' . self::ACADEMY_LINK,
            500,
            'MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED',
        );
    }
}
