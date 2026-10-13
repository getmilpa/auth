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

use Milpa\Auth\Contracts\SessionStore;

/**
 * A session ledger on disk — the persistent counterpart of {@see InMemorySessionStore}, so a session
 * minted in one request is still there in the next.
 *
 * {@see InMemorySessionStore} is enough within a single process (a test, a long-lived worker); a real
 * HTTP login spans separate PHP processes, and needs its sessions to outlive the request that made them.
 * This holds the same fail-closed contract — an expired or revoked record reads as absent, never as a
 * live actor — over a JSON file with locked writes, mirroring the framework's other file stores.
 *
 * THE FILE KEYS A SESSION BY A DIGEST OF ITS ID, NEVER THE ID ITSELF. The session id is a bearer
 * credential: it is exactly the value the browser sends back in the session cookie, and presenting it
 * authenticates. So this store never writes it down — it keys each record by `hash('sha256', $id)` and
 * {@see read()}/{@see destroy()} hash the id the caller presents before looking it up. A read of the
 * file on disk then yields only digests, which open nothing: this is what the sibling stores already do
 * (an API token and an invitation are kept as their sha256). A record carries no id field of its own;
 * {@see read()} hydrates it with the raw id the caller passed, so the cookie keeps carrying the id and
 * nothing downstream changes. One consequence, by design: a sessions file written by an older version —
 * keyed by the raw id — is no longer found by its digest, so sessions open before an upgrade stop
 * resolving and their owners sign in again (a one-time re-authentication, not a loss of any grant).
 */
final class FileSessionStore implements SessionStore
{
    /** @var callable(): \DateTimeImmutable */
    private $clock;

    /** @param (callable(): \DateTimeImmutable)|null $clock the clock expiry is evaluated against */
    public function __construct(private readonly string $path, ?callable $clock = null)
    {
        $this->clock = $clock ?? static fn (): \DateTimeImmutable => new \DateTimeImmutable();
    }

    /** The live session under this id, or null when none is stored, or it is expired or revoked (fail-closed). */
    public function read(string $sessionId): ?SessionRecord
    {
        $entry = $this->all()[self::key($sessionId)] ?? null;
        if (!\is_array($entry)) {
            return null;
        }
        $session = self::hydrate($sessionId, $entry);

        // Fail-closed: an expired or revoked session reads as absent, exactly as in memory.
        return $session !== null && $session->isValid(($this->clock)()) ? $session : null;
    }

    /** Persist a session on disk, keyed by a digest of its id, under an exclusive lock. */
    public function write(SessionRecord $session): void
    {
        $this->mutate(static function (array $map) use ($session): array {
            $map[self::key($session->id)] = [
                'actorId' => $session->actorId,
                'actorType' => $session->actorType->value,
                'createdAt' => $session->createdAt->format(\DateTimeInterface::ATOM),
                'expiresAt' => $session->expiresAt->format(\DateTimeInterface::ATOM),
                'scopes' => $session->scopes,
                'claims' => $session->claims,
                'revoked' => $session->revoked,
            ];

            return $map;
        });
    }

    /** Remove the session under this id; a no-op when none is stored. */
    public function destroy(string $sessionId): void
    {
        $this->mutate(static function (array $map) use ($sessionId): array {
            unset($map[self::key($sessionId)]);

            return $map;
        });
    }

    /**
     * The on-disk key for a session id: its sha256 digest, so a read of the file never yields a usable
     * cookie. The id itself travels only in the cookie; the store keeps the digest the cookie hashes to.
     */
    private static function key(string $sessionId): string
    {
        return hash('sha256', $sessionId);
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function hydrate(string $id, array $entry): ?SessionRecord
    {
        $actorType = ActorType::tryFrom(\is_string($entry['actorType'] ?? null) ? $entry['actorType'] : '');
        $createdAt = self::date($entry['createdAt'] ?? null);
        $expiresAt = self::date($entry['expiresAt'] ?? null);
        if ($actorType === null || $createdAt === null || $expiresAt === null || !\is_string($entry['actorId'] ?? null)) {
            return null;
        }

        return new SessionRecord(
            id: $id,
            actorId: $entry['actorId'],
            actorType: $actorType,
            createdAt: $createdAt,
            expiresAt: $expiresAt,
            scopes: self::strings($entry['scopes'] ?? null),
            claims: \is_array($entry['claims'] ?? null) ? $entry['claims'] : [],
            revoked: (bool) ($entry['revoked'] ?? false),
        );
    }

    private static function date(mixed $value): ?\DateTimeImmutable
    {
        if (!\is_string($value) || $value === '') {
            return null;
        }
        $date = \DateTimeImmutable::createFromFormat(\DateTimeInterface::ATOM, $value);

        return $date === false ? null : $date;
    }

    /** @return list<string> */
    private static function strings(mixed $value): array
    {
        if (!\is_array($value)) {
            return [];
        }
        $out = [];
        foreach ($value as $v) {
            if (\is_string($v)) {
                $out[] = $v;
            }
        }

        return $out;
    }

    /** @return array<string, mixed> */
    private function all(): array
    {
        $raw = is_file($this->path) ? @file_get_contents($this->path) : '';
        $decoded = \is_string($raw) && $raw !== '' ? json_decode($raw, true) : [];

        return \is_array($decoded) ? $decoded : [];
    }

    /** @param callable(array<string, mixed>): array<string, mixed> $fn */
    private function mutate(callable $fn): void
    {
        $dir = \dirname($this->path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0o775, true);
        }
        $fh = @fopen($this->path, 'c+');
        if ($fh === false) {
            return;
        }
        try {
            flock($fh, LOCK_EX);
            $raw = stream_get_contents($fh);
            $decoded = \is_string($raw) && $raw !== '' ? json_decode($raw, true) : [];
            $map = $fn(\is_array($decoded) ? $decoded : []);
            $out = json_encode($map, JSON_UNESCAPED_SLASHES);
            if ($out !== false) {
                ftruncate($fh, 0);
                rewind($fh);
                fwrite($fh, $out);
                fflush($fh);
            }
        } finally {
            flock($fh, LOCK_UN);
            fclose($fh);
        }
    }
}
