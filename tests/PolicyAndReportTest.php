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
use Milpa\Auth\PermissionReport;
use Milpa\Auth\PolicyDecision;
use Milpa\Auth\PolicyEffect;
use Milpa\Auth\Role;
use PHPUnit\Framework\TestCase;

final class PolicyAndReportTest extends TestCase
{
    public function testPolicyDecisionPredicates(): void
    {
        self::assertTrue(PolicyDecision::allow()->isAllowed());
        self::assertTrue(PolicyDecision::deny('nope')->isDenied());
        self::assertSame('nope', PolicyDecision::deny('nope')->reason);
        self::assertTrue(PolicyDecision::abstain()->isAbstain());
        self::assertSame(PolicyEffect::Allow, PolicyDecision::allow()->effect);
    }

    public function testPermissionReportSnapshotsGrantsAndProvenance(): void
    {
        $resolver = new CatalogPermissionResolver(new ArrayPermissionCatalog(
            [Permission::parse('crm.contact:update')],
            [new Role('editor', 'Editor', [Permission::parse('crm.contact:update')])],
        ));
        $actor = new Actor('u1', ActorType::User, roles: ['editor']);
        $report = PermissionReport::of($actor, PermissionContext::none(), $resolver);
        self::assertSame(['editor'], $report->roles);
        self::assertTrue($report->granted->can('contact', 'update', 'crm'));
        self::assertSame('editor', $report->granted->sourcesOf(Permission::parse('crm.contact:update'))[0]->id);
    }
}
