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

namespace Milpa\Auth\Tests;

use Milpa\Auth\ActorType;
use Milpa\Auth\Actor;
use Milpa\Auth\ArrayPermissionCatalog;
use Milpa\Auth\CatalogPermissionResolver;
use Milpa\Auth\Permission;
use Milpa\Auth\PermissionContext;
use Milpa\Auth\PermissionSourceType;
use Milpa\Auth\Role;
use PHPUnit\Framework\TestCase;

final class CatalogPermissionResolverTest extends TestCase
{
    private function resolver(): CatalogPermissionResolver
    {
        return new CatalogPermissionResolver(new ArrayPermissionCatalog(
            [Permission::parse('crm.contact:update')],
            [new Role('editor', 'Editor', [Permission::parse('crm.contact:update')])],
        ));
    }

    public function testRolesExpandWithRoleProvenance(): void
    {
        $actor = new Actor('u1', ActorType::User, roles: ['editor']);
        $set = $this->resolver()->resolve($actor, PermissionContext::none());
        self::assertTrue($set->can('contact', 'update', 'crm'));
        $sources = $set->sourcesOf(Permission::parse('crm.contact:update'));
        self::assertSame(PermissionSourceType::Role, $sources[0]->type);
        self::assertSame('editor', $sources[0]->id);
    }

    public function testUnknownRoleGrantsNothing(): void
    {
        $actor = new Actor('u1', ActorType::User, roles: ['ghost']);
        $set = $this->resolver()->resolve($actor, PermissionContext::none());
        self::assertFalse($set->can('contact', 'update', 'crm'));
    }

    public function testFlatScopesLiftWithScopeProvenance(): void
    {
        $actor = new Actor('u1', ActorType::User, ['crm.contact:read']);
        $set = $this->resolver()->resolve($actor, PermissionContext::none());
        self::assertTrue($set->can('contact', 'read', 'crm'));
        $sources = $set->sourcesOf(Permission::parse('crm.contact:read'));
        self::assertSame(PermissionSourceType::Scope, $sources[0]->type);
        self::assertSame('crm.contact:read', $sources[0]->id);
    }

    public function testWildcardScopeGrantsAll(): void
    {
        $actor = new Actor('root', ActorType::Service, ['*']);
        $set = $this->resolver()->resolve($actor, PermissionContext::none());
        self::assertTrue($set->grantsAll());
        self::assertTrue($set->can('anything', 'goes'));
    }

    public function testNonPermissionScopeIsSkipped(): void
    {
        // A bare scope like 'admin' is not a valid permission key; it is skipped from the set
        // (still checkable via Actor::hasScope) rather than throwing during resolution.
        $actor = new Actor('u1', ActorType::User, ['admin', 'crm.contact:read']);
        $set = $this->resolver()->resolve($actor, PermissionContext::none());
        self::assertTrue($set->can('contact', 'read', 'crm'));
        self::assertCount(1, $set->all());
    }
}
