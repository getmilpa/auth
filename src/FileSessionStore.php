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
        $entry = $this->all()[$sessionId] ?? null;
        if (!\is_array($entry)) {
            return null;
        }
        $session = self::hydrate($sessionId, $entry);

        // Fail-closed: an expired or revoked session reads as absent, exactly as in memory.
        return $session !== null && $session->isValid(($this->clock)()) ? $session : null;
    }

    /** Persist a session on disk, keyed by its id, under an exclusive lock. */
    public function write(SessionRecord $session): void
    {
        $this->mutate(static function (array $map) use ($session): array {
            $map[$session->id] = [
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
            unset($map[$sessionId]);

            return $map;
        });
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
