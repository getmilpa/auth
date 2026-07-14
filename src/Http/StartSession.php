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
use Milpa\Auth\Contracts\SessionStore;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 middleware that resolves the *cookie* credential channel: it reads the session id from
 * the configured cookie, looks it up in the {@see SessionStore}, and attaches the resulting
 * {@see AuthContext} under {@see AuthenticateMiddleware::ATTRIBUTE}. A live session becomes
 * {@see AuthContext::authenticated()}; anything else — no cookie, an unknown id, or a session the
 * store reports as expired or revoked — becomes {@see AuthContext::anonymous()}.
 *
 * Like {@see AuthenticateMiddleware} it only *produces* a context and never throws: the fail-closed
 * decision belongs to {@see RequireScopeMiddleware} downstream, so this composes BEFORE the guard. It
 * carries no clock of its own — {@see SessionStore::read()} is contractually fail-closed (it returns
 * `null` for an expired or revoked record), so a `null` read is the single "not a live session"
 * signal this middleware needs.
 */
final class StartSession implements MiddlewareInterface
{
    /**
     * @param SessionStore $store      where sessions are read from — the storage seam this middleware
     *                                 trusts to be fail-closed
     * @param string       $cookieName the cookie the opaque session id travels in
     */
    public function __construct(
        private readonly SessionStore $store,
        private readonly string $cookieName = 'milpa_session',
    ) {
    }

    /**
     * Resolves the session cookie to an {@see AuthContext}, attaches it under
     * {@see AuthenticateMiddleware::ATTRIBUTE}, and passes the request on — authenticated for a live
     * session, anonymous for everything else.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $context = $this->resolve($request);

        return $handler->handle($request->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $context));
    }

    /**
     * The context the request's session cookie resolves to: authenticated when the store returns a
     * live {@see \Milpa\Auth\SessionRecord}, anonymous when the cookie is absent/blank or the store
     * (fail-closed) reports no live session for it.
     */
    private function resolve(ServerRequestInterface $request): AuthContext
    {
        $sessionId = $request->getCookieParams()[$this->cookieName] ?? null;
        if (!is_string($sessionId) || $sessionId === '') {
            return AuthContext::anonymous();
        }

        $record = $this->store->read($sessionId);
        if ($record === null) {
            return AuthContext::anonymous();
        }

        return AuthContext::authenticated($record->toActor());
    }
}
