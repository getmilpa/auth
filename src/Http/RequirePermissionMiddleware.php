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
use Milpa\Auth\Contracts\PermissionContextFactory;
use Milpa\Auth\Contracts\PermissionResolver;
use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\PermissionDeniedException;
use Milpa\Auth\Permission;
use Milpa\Auth\PermissionContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 gate that authorizes a request against a single required {@see Permission}, beside — never
 * replacing — {@see RequireScopeMiddleware}. Fail-closed and symmetric with the scope gate: no context
 * → 401, not authenticated → 401, permission not held → 403 {@see PermissionDeniedException}. When a
 * {@see PermissionResolver} is injected and no set is attached yet, it resolves once (with the optional
 * {@see PermissionContextFactory}, else {@see PermissionContext::none()}) and re-attaches the context so
 * the handler/report sees it. Resolution precedence: attached set > injected resolver > flat-scope
 * fallback (see {@see AuthContext::can()}).
 */
final class RequirePermissionMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly Permission $required,
        private readonly ?PermissionResolver $resolver = null,
        private readonly ?PermissionContextFactory $contextFactory = null,
    ) {
    }

    /**
     * Authorizes the request against the attached {@see AuthContext}, resolving permissions once via
     * the injected {@see PermissionResolver} when none are attached yet, or throws a typed, learnable
     * denial ({@see AuthContextMissingException} for 401, {@see PermissionDeniedException} for 403).
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $context = $request->getAttribute(AuthenticateMiddleware::ATTRIBUTE);

        if (!$context instanceof AuthContext) {
            throw AuthContextMissingException::notAttached();
        }
        if (!$context->isAuthenticated() || $context->actor === null) {
            throw AuthContextMissingException::unauthenticated();
        }

        if ($context->permissions() === null && $this->resolver !== null) {
            $permissionContext = $this->contextFactory?->fromRequest($request) ?? PermissionContext::none();
            $context = $context->withPermissions($this->resolver->resolve($context->actor, $permissionContext));
            $request = $request->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $context);
        }

        if (!$context->can($this->required->resource, $this->required->action, $this->required->namespace)) {
            throw PermissionDeniedException::forRequired($this->required);
        }

        return $handler->handle($request);
    }
}
