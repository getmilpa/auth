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

use Milpa\Auth\CredentialType;
use PHPUnit\Framework\TestCase;

final class CredentialTypeTest extends TestCase
{
    public function testPasskeyCaseExists(): void
    {
        self::assertSame('passkey', CredentialType::Passkey->value);
        self::assertSame(CredentialType::Passkey, CredentialType::from('passkey'));
    }

    public function testClosedVocabularyKeepsBearerAndCookie(): void
    {
        self::assertSame('bearer', CredentialType::Bearer->value);
        self::assertSame('cookie', CredentialType::Cookie->value);
        self::assertCount(3, CredentialType::cases());
    }
}
