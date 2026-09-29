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

namespace Milpa\Auth\WebAuthn;

/**
 * The relying party a ceremony runs for — resolved per request/tenant, never env-static. `id` is the
 * WebAuthn RP ID (an eTLD+1 or host); `allowedOrigins` is the exact-string allowlist checked against the
 * ceremony's clientDataJSON `origin`. Multi-tenant hosts resolve one per request.
 *
 * A relying party that cannot say where its ceremonies run REFUSES TO EXIST: an empty id, no origins, an
 * origin that is not `https://host[:port]` (plain `http` only on a loopback host), or one whose host is
 * neither the RP ID nor a subdomain of it throws here, at configuration time — never a verifier that has
 * nothing to hold the ceremony's origin to and so accepts whatever page relayed it.
 */
final readonly class RelyingParty
{
    /** Hosts a browser treats as a secure context over plain http. */
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    /**
     * @param list<string> $allowedOrigins exact origins accepted for this RP — scheme, host and port only
     *
     * @throws \InvalidArgumentException when the RP cannot bind a ceremony to where it ran
     */
    public function __construct(
        public string $id,
        public string $name,
        public array $allowedOrigins,
    ) {
        if ($id === '') {
            throw new \InvalidArgumentException('RelyingParty id must not be empty: it is the rpId every ceremony binds to.');
        }
        if ($allowedOrigins === []) {
            throw new \InvalidArgumentException(\sprintf(
                'RelyingParty "%s" needs at least one entry in allowedOrigins (for example "https://%s"): '
                . 'without one no ceremony origin can be checked.',
                $id,
                $id,
            ));
        }
        foreach ($allowedOrigins as $origin) {
            self::assertOrigin($id, $origin);
        }
    }

    /** Whether a ceremony's clientDataJSON `origin` is one this RP allows — exact string match, nothing implied. */
    public function allowsOrigin(string $origin): bool
    {
        return \in_array($origin, $this->allowedOrigins, true);
    }

    private static function assertOrigin(string $id, mixed $origin): void
    {
        if (!\is_string($origin) || preg_match('#^(https?)://([a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?$#', $origin, $m) !== 1) {
            throw new \InvalidArgumentException(\sprintf(
                'RelyingParty "%s" has an allowed origin that is not scheme://host[:port] (lowercase, no path, no wildcard): %s',
                $id,
                \is_string($origin) ? '"' . $origin . '"' : get_debug_type($origin),
            ));
        }
        [, $scheme, $host] = $m;
        if ($scheme !== 'https' && !\in_array($host, self::LOOPBACK_HOSTS, true)) {
            throw new \InvalidArgumentException(\sprintf(
                'RelyingParty "%s" allows origin "%s": it must be https (plain http only on localhost).',
                $id,
                $origin,
            ));
        }
        if ($host !== $id && !str_ends_with($host, '.' . $id)) {
            throw new \InvalidArgumentException(\sprintf(
                'RelyingParty "%s" allows origin "%s", whose host is neither %s nor a subdomain of it.',
                $id,
                $origin,
                $id,
            ));
        }
    }
}
