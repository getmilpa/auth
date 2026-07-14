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

namespace Milpa\Auth\Contracts;

use Milpa\Auth\SessionRecord;

/**
 * Where sessions live — the storage seam for opaque, revocable, expiring server-side sessions. This
 * is the package's central act of restraint: auth defines *what* it needs from storage (read a
 * record by id, write one, destroy one) and a downstream package decides *how* — a `milpa/data`
 * backend, Redis, a database table. Auth never reaches for a database of its own.
 *
 * Implementations MUST be fail-closed on read: {@see self::read()} returns `null` not only for an
 * absent id but for any record that is no longer valid (expired or revoked), so a stale session can
 * never resurrect an actor.
 */
interface SessionStore
{
    /**
     * The session stored under `$sessionId`, or `null` when none is stored — or when the stored one
     * is no longer valid (expired or revoked). Fail-closed: an invalid session reads as absent.
     */
    public function read(string $sessionId): ?SessionRecord;

    /**
     * Persists `$session`, keyed by its {@see SessionRecord::$id} — issuing a new session or
     * replacing an existing one under the same id.
     */
    public function write(SessionRecord $session): void;

    /**
     * Removes the session stored under `$sessionId` — the hard revocation path. A no-op when none is
     * stored.
     */
    public function destroy(string $sessionId): void;
}
