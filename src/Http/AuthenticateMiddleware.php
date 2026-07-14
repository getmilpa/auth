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

namespace Milpa\Auth\Http;

use Milpa\Auth\AuthContext;
use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\Credential;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 entry point that turns an `Authorization: Bearer …` token into a trusted
 * {@see AuthContext} and attaches it to the request under {@see self::ATTRIBUTE}. It only *produces*
 * the context; it never decides whether the request may proceed — that is
 * {@see RequireScopeMiddleware}'s job. So it NEVER throws for a missing or bad credential: a request
 * with no Bearer token flows on with {@see AuthContext::anonymous()}, a rejected one with
 * {@see AuthContext::invalid()}, and only the guard downstream turns those into a 401.
 *
 * The credential split, made explicit: this middleware resolves the *Bearer* channel only. A session
 * *cookie* is also a credential, but resolving it is a session lookup that belongs to
 * {@see StartSession} (which owns the {@see \Milpa\Auth\Contracts\SessionStore}) — this middleware
 * defers the cookie entirely to StartSession and never touches it.
 *
 * The raw token is wrapped in a {@see Credential} the instant it leaves the header and never appears
 * anywhere else: not in the context, not in a log, not in an error.
 */
final class AuthenticateMiddleware implements MiddlewareInterface
{
    /**
     * The PSR-7 request attribute the whole auth pipeline reads and writes the {@see AuthContext} on.
     */
    public const ATTRIBUTE = 'milpa.auth';

    private const BEARER_PREFIX = 'Bearer ';

    /**
     * @param CredentialVerifier $verifier the producer that turns a {@see Credential} into a context
     */
    public function __construct(
        private readonly CredentialVerifier $verifier,
    ) {
    }

    /**
     * Resolves the Bearer credential (if any) to an {@see AuthContext}, attaches it under
     * {@see self::ATTRIBUTE}, and passes the request on. Fail-open on *authentication*, fail-closed on
     * *authorization*: it always continues the pipeline, leaving the decision to the guard.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->bearerToken($request);
        $context = $token === null
            ? AuthContext::anonymous()
            : $this->verifier->verify(Credential::bearer($token));

        return $handler->handle($request->withAttribute(self::ATTRIBUTE, $context));
    }

    /**
     * The token from an `Authorization: Bearer …` header, or `null` when the header is absent, is not
     * a Bearer header, or carries an empty token. The value is only ever returned to be wrapped in a
     * {@see Credential} — it is never logged.
     */
    private function bearerToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine('Authorization');
        if (!str_starts_with($header, self::BEARER_PREFIX)) {
            return null;
        }

        $token = substr($header, strlen(self::BEARER_PREFIX));

        return $token === '' ? null : $token;
    }
}
