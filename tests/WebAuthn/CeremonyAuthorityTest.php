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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The four symbols app-docentes already imports must resolve from THIS package, once.
 *
 * milpa/auth-webauthn used to declare the same Milpa\Auth\WebAuthn\* prefix. Authority for the
 * ceremony vocabulary (RelyingParty, WebAuthnVerifier, assertion result, authentication response)
 * lives here; the adapter package must not define these types.
 */
final class CeremonyAuthorityTest extends TestCase
{
    /** @return list<array{0: class-string, 1: bool}> */
    public static function appDocentesSymbols(): array
    {
        return [
            ['Milpa\\Auth\\WebAuthn\\RelyingParty', false],
            ['Milpa\\Auth\\WebAuthn\\Contracts\\WebAuthnVerifier', true],
            ['Milpa\\Auth\\WebAuthn\\WebAuthnAssertionResult', false],
            ['Milpa\\Auth\\WebAuthn\\WebAuthnAuthenticationResponse', false],
        ];
    }

    /** @param class-string $fqcn */
    #[DataProvider('appDocentesSymbols')]
    public function testAppDocentesSymbolResolvesOnceFromThisPackage(string $fqcn, bool $isInterface): void
    {
        if ($isInterface) {
            self::assertTrue(interface_exists($fqcn), $fqcn . ' must be an interface in milpa/auth');
        } else {
            self::assertTrue(class_exists($fqcn), $fqcn . ' must be a class in milpa/auth');
        }

        $file = (new \ReflectionClass($fqcn))->getFileName();
        self::assertNotFalse($file, $fqcn . ' has no source file');
        $real = realpath($file);
        self::assertNotFalse($real);
        $src = realpath(dirname(__DIR__, 2) . '/src/WebAuthn');
        self::assertNotFalse($src);
        self::assertStringStartsWith($src, $real, $fqcn . ' must be defined under src/WebAuthn of milpa/auth');
    }

    public function testTheFourSymbolsAreInstantiableOrInterfaces(): void
    {
        $rp = new \Milpa\Auth\WebAuthn\RelyingParty('crm.example', 'Acme CRM', ['https://crm.example']);
        self::assertSame('crm.example', $rp->id);

        $response = new \Milpa\Auth\WebAuthn\WebAuthnAuthenticationResponse(
            'cred-b64',
            "\x01client",
            "\x02auth",
            "\x03sig",
            'user-handle',
        );
        self::assertSame('cred-b64', $response->credentialId);
        self::assertSame("\x03sig", $response->signature());

        $result = new \Milpa\Auth\WebAuthn\WebAuthnAssertionResult('cred-b64', 'actor-1', 'user-handle', 1, false);
        self::assertSame('actor-1', $result->actorId);

        $verifier = new \ReflectionClass(\Milpa\Auth\WebAuthn\Contracts\WebAuthnVerifier::class);
        self::assertTrue($verifier->isInterface());
        self::assertCount(4, $verifier->getMethods());
    }
}
