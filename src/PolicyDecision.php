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

/** A {@see Contracts\Policy}'s verdict on one (actor, permission, context) — an effect plus an optional learnable reason. */
final readonly class PolicyDecision
{
    public function __construct(
        public PolicyEffect $effect,
        public ?string $reason = null,
    ) {
    }

    /** Factory for an allow decision. */
    public static function allow(?string $reason = null): self
    {
        return new self(PolicyEffect::Allow, $reason);
    }

    /** Factory for a deny decision. */
    public static function deny(?string $reason = null): self
    {
        return new self(PolicyEffect::Deny, $reason);
    }

    /** Factory for an abstain decision. */
    public static function abstain(): self
    {
        return new self(PolicyEffect::Abstain);
    }

    /** Check if the decision is allow. */
    public function isAllowed(): bool
    {
        return $this->effect === PolicyEffect::Allow;
    }

    /** Check if the decision is deny. */
    public function isDenied(): bool
    {
        return $this->effect === PolicyEffect::Deny;
    }

    /** Check if the decision is abstain. */
    public function isAbstain(): bool
    {
        return $this->effect === PolicyEffect::Abstain;
    }
}
