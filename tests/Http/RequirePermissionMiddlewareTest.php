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

namespace Milpa\Auth\Tests\Http;

use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\ArrayPermissionCatalog;
use Milpa\Auth\AuthContext;
use Milpa\Auth\CatalogPermissionResolver;
use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\PermissionDeniedException;
use Milpa\Auth\Http\AuthenticateMiddleware;
use Milpa\Auth\Http\RequirePermissionMiddleware;
use Milpa\Auth\Permission;
use Milpa\Auth\Role;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RequirePermissionMiddlewareTest extends HttpMiddlewareTestCase
{
    private function resolver(): CatalogPermissionResolver
    {
        return new CatalogPermissionResolver(new ArrayPermissionCatalog(
            [Permission::parse('crm.contact:update')],
            [new Role('editor', 'Editor', [Permission::parse('crm.contact:update')])],
        ));
    }

    public function testPassesWhenActorHoldsPermissionViaRole(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $ctx = AuthContext::authenticated(new Actor('u1', ActorType::User, roles: ['editor']));
        $request = $this->request()->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $ctx);
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:update'), $this->resolver());
        $handler = $this->handler($response);

        $result = $mw->process($request, $handler);

        $this->assertSame($response, $result);
    }

    public function testTheResolvedPermissionSetIsReAttachedForTheHandler(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $ctx = AuthContext::authenticated(new Actor('u1', ActorType::User, roles: ['editor']));
        $request = $this->request()->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $ctx);
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:update'), $this->resolver());

        // The handler asserts, against the request it actually receives, that the resolved permission
        // set was re-attached (not just mutated on a local copy). expects(once) proves the body ran.
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->willReturnCallback(function (ServerRequestInterface $received) use ($response): ResponseInterface {
                $reattached = $received->getAttribute(AuthenticateMiddleware::ATTRIBUTE);
                $this->assertInstanceOf(AuthContext::class, $reattached);
                $this->assertNotNull(
                    $reattached->permissions(),
                    'the resolved PermissionSet must be re-attached to the request the handler receives',
                );

                return $response;
            });

        $mw->process($request, $handler);
    }

    public function testDeniesWithoutRole(): void
    {
        $ctx = AuthContext::authenticated(new Actor('u1', ActorType::User));
        $request = $this->request()->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $ctx);
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:update'), $this->resolver());
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        try {
            $mw->process($request, $handler);
            $this->fail('expected PermissionDeniedException');
        } catch (PermissionDeniedException $e) {
            $this->assertSame(403, $e->statusCode());
            $this->assertSame('MILPA_PERMISSION_DENIED', $e->errorCode());
        }
    }

    public function testFlatScopeBcPathWithoutResolver(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $ctx = AuthContext::authenticated(new Actor('u1', ActorType::User, ['crm.contact:read']));
        $request = $this->request()->withAttribute(AuthenticateMiddleware::ATTRIBUTE, $ctx);
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:read')); // no resolver → flat fallback
        $handler = $this->handler($response);

        $result = $mw->process($request, $handler);

        $this->assertSame($response, $result);
    }

    public function testMissingContextIs401(): void
    {
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:update'));
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        try {
            $mw->process($this->request(), $handler);
            $this->fail('expected AuthContextMissingException');
        } catch (AuthContextMissingException $e) {
            $this->assertSame(401, $e->statusCode());
            $this->assertSame('MILPA_AUTH_CONTEXT_MISSING', $e->errorCode());
        }
    }

    public function testUnauthenticatedIs401(): void
    {
        $request = $this->request()->withAttribute(AuthenticateMiddleware::ATTRIBUTE, AuthContext::anonymous());
        $mw = new RequirePermissionMiddleware(Permission::parse('crm.contact:update'), $this->resolver());
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        try {
            $mw->process($request, $handler);
            $this->fail('expected AuthContextMissingException');
        } catch (AuthContextMissingException $e) {
            $this->assertSame(401, $e->statusCode());
            $this->assertSame('MILPA_UNAUTHENTICATED', $e->errorCode());
        }
    }
}
