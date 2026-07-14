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
use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\ScopeDeniedException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 guard that decides whether a request may proceed, reading the {@see AuthContext} that
 * {@see AuthenticateMiddleware} (or {@see StartSession}) attached under
 * {@see AuthenticateMiddleware::ATTRIBUTE}. It is the fail-closed gate the whole pipeline exists for,
 * and it distinguishes three refusals so the caller learns exactly what to fix:
 *
 *   - no context on the request at all → 401 {@see AuthContextMissingException::notAttached()}
 *     (the pipeline is misconfigured — this guard ran before anything produced a context);
 *   - a context, but anonymous or invalid → 401 {@see AuthContextMissingException::unauthenticated()}
 *     (the request never authenticated);
 *   - authenticated, but holding none of the required scopes → 403 {@see ScopeDeniedException}.
 *
 * It passes through only when the actor holds at least one required scope. An instance built with no
 * scopes therefore denies every request — a deliberately fail-closed footgun, not a pass-all.
 */
final class RequireScopeMiddleware implements MiddlewareInterface
{
    /** @var list<string> */
    private readonly array $scopes;

    /**
     * @param string ...$scopes the scopes any one of which admits the request
     */
    public function __construct(string ...$scopes)
    {
        $this->scopes = array_values($scopes);
    }

    /**
     * Authorizes the request against the attached {@see AuthContext}, or throws a typed, learnable
     * denial ({@see AuthContextMissingException} for 401, {@see ScopeDeniedException} for 403). Passes
     * the request on untouched when a required scope is held.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $context = $request->getAttribute(AuthenticateMiddleware::ATTRIBUTE);

        if (!$context instanceof AuthContext) {
            throw AuthContextMissingException::notAttached();
        }

        if (!$context->isAuthenticated()) {
            throw AuthContextMissingException::unauthenticated();
        }

        if (!$context->hasAnyScope($this->scopes)) {
            throw ScopeDeniedException::forRequiredScopes($this->scopes);
        }

        return $handler->handle($request);
    }
}
