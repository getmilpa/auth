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
 * A challenge ledger on disk: each issued challenge kept until it is consumed once or expires.
 *
 * The shape mirrors the framework's other file stores — an exclusive lock around every mutation, JSON on
 * disk. Consuming a challenge DELETES it, so a second attempt with the same one finds nothing: single-use
 * is enforced by removal, not by a flag someone could forget to check.
 */
final class FileChallengeStore implements ChallengeStore
{
    /** @var callable(): int */
    private $clock;

    /**
     * @param string                 $path       where the ledger lives on disk
     * @param int                    $ttlSeconds how long an issued challenge stays acceptable
     * @param (callable(): int)|null $clock      the current unix time, injectable for tests
     */
    public function __construct(
        private readonly string $path,
        private readonly int $ttlSeconds = 300,
        ?callable $clock = null,
    ) {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /** Mint a fresh random challenge, keep it until it expires, and return its raw bytes. */
    public function issue(): string
    {
        $challenge = random_bytes(32);
        $key = bin2hex($challenge);
        $expires = ($this->clock)() + $this->ttlSeconds;
        $this->mutate(static function (array $map) use ($key, $expires): array {
            $map[$key] = $expires;

            return $map;
        });

        return $challenge;
    }

    /** Accept a challenge once — true if issued and unexpired, then deleted so it can never be true again. */
    public function consume(string $challenge): bool
    {
        $key = bin2hex($challenge);
        $now = ($this->clock)();
        $ok = false;
        $this->mutate(static function (array $map) use ($key, $now, &$ok): array {
            $expires = $map[$key] ?? null;
            if (\is_int($expires) && $expires >= $now) {
                $ok = true;
            }
            // Whether accepted or expired, it is gone now — a challenge is used at most once.
            unset($map[$key]);

            return $map;
        });

        return $ok;
    }

    /** @param callable(array<string, int>): array<string, int> $fn */
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
            $map = \is_array($decoded) ? $decoded : [];

            /** @var array<string, int> $typed */
            $typed = [];
            foreach ($map as $k => $v) {
                if (\is_string($k) && \is_int($v)) {
                    $typed[$k] = $v;
                }
            }
            $typed = $fn($typed);

            $out = json_encode($typed);
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
