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

/**
 * A single authorization capability, addressed by the canonical key `{namespace}.{resource}:{action}`
 * (namespace optional). It is the atom of the permissions matrix: roles group these, the resolver
 * grants them, and `can()` checks them. Value identity is the key alone — {@see self::$metadata} is
 * non-authoritative. Immutable by construction.
 */
final readonly class Permission
{
    /**
     * @param array<string,mixed> $metadata non-authoritative extra detail; excluded from key()/equals()
     */
    public function __construct(
        public string $resource,
        public string $action,
        public ?string $namespace = null,
        public array $metadata = [],
    ) {
    }

    /** The canonical string: `{namespace}.{resource}:{action}`, or `{resource}:{action}` when namespace is null. */
    public function key(): string
    {
        return $this->namespace !== null
            ? "{$this->namespace}.{$this->resource}:{$this->action}"
            : "{$this->resource}:{$this->action}";
    }

    /** Builds a Permission straight from its segments, without parsing a key string. */
    public static function of(string $resource, string $action, ?string $namespace = null): self
    {
        return new self($resource, $action, $namespace);
    }

    /**
     * Parses a canonical key. `action` is everything after the single `:`; of the pre-colon part, the
     * segment after the last `.` is the resource and the rest is the namespace (null if no `.`). A key
     * with no `:`, an empty segment, or more than one `:` is malformed — fail-closed.
     *
     * @throws \InvalidArgumentException on a malformed key
     */
    public static function parse(string $key): self
    {
        $colon = strrpos($key, ':');
        if ($colon === false || $colon === 0 || $colon === \strlen($key) - 1) {
            throw new \InvalidArgumentException(
                "[MILPA_PERMISSION_MALFORMED] '{$key}' is not a valid permission key. Expected "
                . "'{namespace}.{resource}:{action}' (namespace optional), e.g. 'crm.contact:create' or 'posts:read'."
            );
        }
        $action = substr($key, $colon + 1);
        $left = substr($key, 0, $colon);
        if (str_contains($left, ':')) {
            throw new \InvalidArgumentException("[MILPA_PERMISSION_MALFORMED] '{$key}' has more than one ':'.");
        }
        $dot = strrpos($left, '.');
        if ($dot === false) {
            return new self($left, $action);
        }
        if ($dot === 0 || $dot === \strlen($left) - 1) {
            throw new \InvalidArgumentException("[MILPA_PERMISSION_MALFORMED] '{$key}' has an empty namespace or resource segment.");
        }

        return new self(substr($left, $dot + 1), $action, substr($left, 0, $dot));
    }

    /** Value equality by canonical key (metadata is not part of identity). */
    public function equals(self $other): bool
    {
        return $this->key() === $other->key();
    }
}
