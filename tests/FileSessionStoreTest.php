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
use Milpa\Auth\FileSessionStore;
use Milpa\Auth\SessionRecord;
use PHPUnit\Framework\TestCase;

/** A session survives on disk across instances, and reads fail-closed once expired or revoked. */
final class FileSessionStoreTest extends TestCase
{
    private string $path;

    private \DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/milpa-sess-' . bin2hex(random_bytes(4)) . '.json';
        $this->now = new \DateTimeImmutable('2026-08-27T12:00:00+00:00');
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testASessionSurvivesAcrossInstances(): void
    {
        $record = $this->record('sess-1', $this->now->add(new \DateInterval('PT1H')), ['agent:read', 'agent:answer']);
        $this->store()->write($record);

        // A FRESH store instance (the next request) reads it back from disk — this is the whole point.
        $read = $this->store()->read('sess-1');

        self::assertNotNull($read);
        self::assertSame('sess-1', $read->id);
        self::assertSame('passkey:cred', $read->actorId);
        self::assertSame(ActorType::User, $read->actorType);
        self::assertSame(['agent:read', 'agent:answer'], $read->scopes);
    }

    public function testAnExpiredSessionReadsAsAbsent(): void
    {
        $this->store()->write($this->record('sess-1', $this->now->sub(new \DateInterval('PT1S')), []));

        self::assertNull($this->store()->read('sess-1'), 'expired is fail-closed');
    }

    public function testARevokedSessionReadsAsAbsent(): void
    {
        $this->store()->write($this->record('sess-1', $this->now->add(new \DateInterval('PT1H')), [], revoked: true));

        self::assertNull($this->store()->read('sess-1'));
    }

    public function testAnUnknownSessionIsNull(): void
    {
        self::assertNull($this->store()->read('never'));
    }

    public function testDestroyRemovesTheSession(): void
    {
        $this->store()->write($this->record('sess-1', $this->now->add(new \DateInterval('PT1H')), []));
        self::assertNotNull($this->store()->read('sess-1'));

        $this->store()->destroy('sess-1');

        self::assertNull($this->store()->read('sess-1'));
    }

    public function testACorruptEntryReadsAsAbsent(): void
    {
        file_put_contents($this->path, (string) json_encode([hash('sha256', 'sess-1') => ['actorId' => 42, 'actorType' => 'nope']]));

        self::assertNull($this->store()->read('sess-1'), 'a malformed record is not a live actor');
    }

    public function testNonArrayScopesHydrateAsEmpty(): void
    {
        // A valid record whose scopes field is not a list still reads — as a session with no scopes. The
        // entry is keyed by the id's digest, as the store writes it, not by the raw id.
        file_put_contents($this->path, (string) json_encode([hash('sha256', 'sess-1') => [
            'actorId' => 'passkey:cred',
            'actorType' => 'user',
            'createdAt' => $this->now->format(\DateTimeInterface::ATOM),
            'expiresAt' => $this->now->add(new \DateInterval('PT1H'))->format(\DateTimeInterface::ATOM),
            'scopes' => 'not-a-list',
        ]]));

        $read = $this->store()->read('sess-1');
        self::assertNotNull($read);
        self::assertSame([], $read->scopes);
    }

    public function testTheFileNeverHoldsTheRawSessionIdOnlyItsDigest(): void
    {
        // The session id is the cookie value, a bearer credential: the file must not write it down. It
        // keys the record by the id's sha256 instead, so a read of the file yields a digest that opens
        // nothing — the same restraint the token and invitation stores already keep.
        $id = bin2hex(random_bytes(32));
        $this->store()->write($this->record($id, $this->now->add(new \DateInterval('PT1H')), ['milpa.admin']));

        $onDisk = (string) file_get_contents($this->path);
        self::assertStringNotContainsString($id, $onDisk, 'the raw session id must never land on disk');
        self::assertStringContainsString(hash('sha256', $id), $onDisk, 'the record is keyed by the id digest');

        // The cookie still carries the raw id, so a read by it round-trips to the same session.
        $read = $this->store()->read($id);
        self::assertNotNull($read);
        self::assertSame($id, $read->id);
        self::assertSame(['milpa.admin'], $read->scopes);
    }

    public function testASessionWrittenRawByAnOlderVersionReadsAsAbsent(): void
    {
        // Upgrade semantics, measured here: a file an older version wrote — keyed by the raw id — is no
        // longer found by the id's digest, so a session open before the upgrade stops resolving and its
        // owner signs in again. No grant is lost; only the live session is.
        file_put_contents($this->path, (string) json_encode(['sess-legacy' => [
            'actorId' => 'passkey:cred',
            'actorType' => 'user',
            'createdAt' => $this->now->format(\DateTimeInterface::ATOM),
            'expiresAt' => $this->now->add(new \DateInterval('PT1H'))->format(\DateTimeInterface::ATOM),
            'scopes' => ['milpa.admin'],
        ]]));

        self::assertNull($this->store()->read('sess-legacy'), 'a raw-keyed legacy session no longer resolves');
    }

    public function testItCreatesItsDirectoryThenPersists(): void
    {
        $path = sys_get_temp_dir() . '/milpa-sess-new-' . bin2hex(random_bytes(4)) . '/nested/s.json';
        $store = new FileSessionStore($path, fn (): \DateTimeImmutable => $this->now);
        $store->write($this->record('s', $this->now->add(new \DateInterval('PT1H')), []));

        self::assertNotNull((new FileSessionStore($path, fn (): \DateTimeImmutable => $this->now))->read('s'));
        @unlink($path);
        @rmdir(\dirname($path));
        @rmdir(\dirname($path, 2));
    }

    public function testAnUnopenablePathLosesTheWriteWithoutThrowing(): void
    {
        $blocker = sys_get_temp_dir() . '/milpa-sblock-' . bin2hex(random_bytes(4));
        file_put_contents($blocker, 'x');
        $store = new FileSessionStore($blocker . '/s.json', fn (): \DateTimeImmutable => $this->now);

        $store->write($this->record('s', $this->now->add(new \DateInterval('PT1H')), [])); // must not throw
        $store->destroy('s'); // must not throw
        self::assertNull($store->read('s'));
        @unlink($blocker);
    }

    private function store(): FileSessionStore
    {
        return new FileSessionStore($this->path, fn (): \DateTimeImmutable => $this->now);
    }

    /** @param list<string> $scopes */
    private function record(string $id, \DateTimeImmutable $expires, array $scopes, bool $revoked = false): SessionRecord
    {
        return new SessionRecord(
            id: $id,
            actorId: 'passkey:cred',
            actorType: ActorType::User,
            createdAt: $this->now,
            expiresAt: $expires,
            scopes: $scopes,
            revoked: $revoked,
        );
    }
}
