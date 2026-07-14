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

namespace Milpa\Auth;

use Milpa\Auth\Contracts\PermissionResolver;

/**
 * A snapshot of what an actor can do in a context and WHY — actor, context, the roles it holds, and the
 * resolved {@see PermissionSet} carrying per-permission provenance. The Admin-readiness seam. It answers
 * "what / why / from where", never "why did this specific action fail" (that is per-check, and lives in
 * {@see Exceptions\PermissionDeniedException}). Carries no denied/warnings and no timestamp.
 */
final readonly class PermissionReport
{
    /**
     * Constructor for a permission report.
     *
     * @param list<string> $roles the role ids the actor holds
     */
    public function __construct(
        public Actor $actor,
        public PermissionContext $context,
        public array $roles,
        public PermissionSet $granted,
    ) {
    }

    /** Create a permission report from an actor, context, and permission resolver. */
    public static function of(Actor $actor, PermissionContext $context, PermissionResolver $resolver): self
    {
        return new self($actor, $context, $actor->roles, $resolver->resolve($actor, $context));
    }
}
