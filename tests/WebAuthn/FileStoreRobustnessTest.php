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

namespace Milpa\Auth\Tests\WebAuthn;

use Milpa\Auth\WebAuthn\FileChallengeStore;
use Milpa\Auth\WebAuthn\FilePasskeyCredentialStore;
use Milpa\Auth\WebAuthn\RegisteredCredential;
use PHPUnit\Framework\TestCase;

/** The file stores create their directory when missing, and lose the write (never throw) when they cannot open it. */
final class FileStoreRobustnessTest extends TestCase
{
    private string $blocker;

    protected function setUp(): void
    {
        // A regular FILE used as if it were a directory: a path under it cannot be opened.
        $this->blocker = sys_get_temp_dir() . '/milpa-block-' . bin2hex(random_bytes(4));
        file_put_contents($this->blocker, 'x');
    }

    protected function tearDown(): void
    {
        @unlink($this->blocker);
    }

    public function testChallengeStoreCreatesItsDirectoryThenWorks(): void
    {
        $path = sys_get_temp_dir() . '/milpa-new-' . bin2hex(random_bytes(4)) . '/nested/ch.json';
        $store = new FileChallengeStore($path);

        $c = $store->issue();
        self::assertTrue($store->consume($c));

        @unlink($path);
        @rmdir(\dirname($path));
        @rmdir(\dirname($path, 2));
    }

    public function testAnUnopenablePathLosesTheWriteWithoutThrowing(): void
    {
        // Path lives "under" a regular file, so mkdir fails and fopen returns false.
        $challenges = new FileChallengeStore($this->blocker . '/ch.json');
        self::assertFalse($challenges->consume('anything'), 'nothing was ever issued, and nothing threw');

        $credentials = new FilePasskeyCredentialStore($this->blocker . '/cr.json');
        $credentials->register(new RegisteredCredential('c', 'pem', 0)); // must not throw
        self::assertNull($credentials->find('c'), 'the write was lost, not raised');
    }
}
