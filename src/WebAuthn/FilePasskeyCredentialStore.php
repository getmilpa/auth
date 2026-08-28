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

/** A registered-passkey ledger on disk: credentialId -> {publicKeyPem, signCount}, locked writes. */
final class FilePasskeyCredentialStore implements PasskeyCredentialStore
{
    public function __construct(private readonly string $path)
    {
    }

    /** Persist a registered credential, keyed by its id. */
    public function register(RegisteredCredential $credential): void
    {
        $this->mutate(static function (array $map) use ($credential): array {
            $map[$credential->credentialId] = ['pem' => $credential->publicKeyPem, 'signCount' => $credential->signCount];

            return $map;
        });
    }

    /** Read a registered credential by id, or null when the house never registered it. */
    public function find(string $credentialId): ?RegisteredCredential
    {
        $entry = $this->read()[$credentialId] ?? null;
        if (!\is_array($entry) || !\is_string($entry['pem'] ?? null)) {
            return null;
        }

        return new RegisteredCredential($credentialId, $entry['pem'], \is_int($entry['signCount'] ?? null) ? $entry['signCount'] : 0);
    }

    /** Advance a credential's stored sign counter after a successful assertion. */
    public function updateSignCount(string $credentialId, int $signCount): void
    {
        $this->mutate(static function (array $map) use ($credentialId, $signCount): array {
            if (isset($map[$credentialId]) && \is_array($map[$credentialId])) {
                $map[$credentialId]['signCount'] = $signCount;
            }

            return $map;
        });
    }

    /** @return array<string, mixed> */
    private function read(): array
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
            $out = json_encode($map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
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
