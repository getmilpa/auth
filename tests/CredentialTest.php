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

use Milpa\Auth\Credential;
use Milpa\Auth\CredentialType;
use PHPUnit\Framework\TestCase;

/**
 * The adversarial suite for {@see Credential}. It pins the FULL leak-vector matrix against the
 * idiomatic secret-bearing shape (private + `#[\SensitiveParameter]` + redacted `__debugInfo` +
 * `__serialize`/`__clone` refusing + NO `__toString`), under BOTH `zend.exception_ignore_args=0`
 * (stack-trace args EXPOSED — the imperfect-environment case) and the hardened default.
 *
 * Honest classification, verified by these tests:
 *   - SEALED BY THE IDIOM: print_r, var_dump, __debugInfo (redacted); json_encode & external-scope
 *     get_object_vars (the private property never crosses the class boundary); serialize & clone
 *     (throw); the stack-trace arg dump of a method holding the Credential (an object arg is never
 *     expanded, and a `#[\SensitiveParameter]` string is redacted even at ignore_args=0).
 *   - KNOWN LEAK (documented boundary, pending Rod's final call): var_export() and the (array) cast
 *     BOTH reach the raw private property — neither consults __debugInfo. Policy until decided
 *     otherwise: never var_export() or (array)-cast a Credential. The two canary tests below pin that
 *     reality and fail loudly if a future PHP release changes it.
 */
final class CredentialTest extends TestCase
{
    private const SECRET = 'super-secret-token';

    private string $originalIgnoreArgs;

    protected function setUp(): void
    {
        $this->originalIgnoreArgs = (string) ini_get('zend.exception_ignore_args');
    }

    protected function tearDown(): void
    {
        ini_set('zend.exception_ignore_args', $this->originalIgnoreArgs);
    }

    // ---------------------------------------------------------------- factories / accessors

    public function testBearerFactorySetsTheTypeAndKeepsTheValue(): void
    {
        $cred = Credential::bearer('abc123');

        $this->assertSame(CredentialType::Bearer, $cred->type);
        $this->assertSame('abc123', $cred->value());
    }

    public function testCookieFactorySetsTheTypeAndKeepsTheValue(): void
    {
        $cred = Credential::cookie('sess-xyz');

        $this->assertSame(CredentialType::Cookie, $cred->type);
        $this->assertSame('sess-xyz', $cred->value());
    }

    public function testConstructorTakesTheTypeAsAClosedVocabulary(): void
    {
        // The type is a CredentialType enum, not a free string: the vocabulary is closed
        // (consistent with ActorType). An arbitrary string would be a TypeError at the call site.
        $cred = new Credential('raw', CredentialType::Bearer);

        $this->assertSame(CredentialType::Bearer, $cred->type);
        $this->assertSame('bearer', $cred->type->value);
        $this->assertSame('raw', $cred->value());
    }

    // ---------------------------------------------------------------- SEALED-BY-IDIOM vectors

    public function testPrintRRedactsTheValue(): void
    {
        // print_r consults __debugInfo in this PHP; the value renders as [redacted].
        $this->assertStringNotContainsString(self::SECRET, print_r(Credential::bearer(self::SECRET), true));
    }

    public function testVarDumpRedactsTheValue(): void
    {
        ob_start();
        var_dump(Credential::bearer(self::SECRET));
        $dump = (string) ob_get_clean();

        $this->assertStringNotContainsString(self::SECRET, $dump);
        $this->assertStringContainsString('[redacted]', $dump);
    }

    public function testDebugInfoRedactsTheValue(): void
    {
        $info = Credential::bearer(self::SECRET)->__debugInfo();

        $this->assertSame('bearer', $info['type']);
        $this->assertSame('[redacted]', $info['value']);
        $this->assertStringNotContainsString(
            self::SECRET,
            implode('|', array_map('strval', $info)),
        );
    }

    public function testJsonEncodeNeverEmitsTheValue(): void
    {
        // json_encode serialises only public properties; the private value can't ride out.
        $json = (string) json_encode(Credential::bearer(self::SECRET));

        $this->assertStringNotContainsString(self::SECRET, $json);
        $this->assertSame('{"type":"bearer"}', $json);
    }

    public function testGetObjectVarsFromOutsideExposesOnlyPublicProperties(): void
    {
        // From outside the class scope get_object_vars() returns only public props — never $value.
        $vars = get_object_vars(Credential::bearer(self::SECRET));

        $this->assertArrayNotHasKey('value', $vars);
        $this->assertArrayHasKey('type', $vars);
        $this->assertStringNotContainsString(self::SECRET, print_r($vars, true));
    }

    // ---------------------------------------------------------------- REFUSING vectors

    public function testSerializeIsRefusedExplicitlyRatherThanIncidentally(): void
    {
        $cred = Credential::bearer(self::SECRET);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(
            'Credential must not be serialized — it carries a secret; persist a SessionRecord instead.',
        );

        serialize($cred);
    }

    public function testSerializeNeverEmitsTheValueEvenAsItRefuses(): void
    {
        $cred = Credential::bearer(self::SECRET);

        try {
            serialize($cred);
            $this->fail('serialize() must refuse a Credential.');
        } catch (\LogicException $e) {
            $this->assertStringNotContainsString(self::SECRET, $e->getMessage());
            $this->assertStringNotContainsString(self::SECRET, $e->getTraceAsString());
        }
    }

    public function testCloneIsRefused(): void
    {
        // A Credential carries a secret; it must never be silently duplicated.
        $cred = Credential::bearer(self::SECRET);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('must not be cloned');

        $ignored = clone $cred;
    }

    public function testCloneNeverEmitsTheValueEvenAsItRefuses(): void
    {
        $cred = Credential::bearer(self::SECRET);

        try {
            $ignored = clone $cred;
            $this->fail('clone must refuse a Credential.');
        } catch (\LogicException $e) {
            $this->assertStringNotContainsString(self::SECRET, $e->getMessage());
            $this->assertStringNotContainsString(self::SECRET, $e->getTraceAsString());
        }
    }

    public function testCastingToStringRaisesAnErrorRatherThanLeaking(): void
    {
        // There is deliberately NO __toString: (string) $cred must blow up at the call site,
        // never quietly return a redaction that a reader could mistake for the real value.
        $cred = Credential::bearer(self::SECRET);

        $this->expectException(\Error::class);
        $this->expectExceptionMessage('could not be converted to string');

        /** @phpstan-ignore-next-line — intentionally exercising the forbidden cast */
        $ignored = (string) $cred;
    }

    // ---------------------------------------------------------------- STACK-TRACE vector (both ini modes)

    public function testTheValueNeverLeaksThroughAStackTraceOfAMethodHoldingIt(): void
    {
        $cred = Credential::bearer(self::SECRET);

        foreach (['0', '1'] as $ignoreArgs) {
            ini_set('zend.exception_ignore_args', $ignoreArgs);

            try {
                $this->throwWhileHolding($cred);
                $this->fail('the method must throw.');
            } catch (\RuntimeException $e) {
                $ctx = "zend.exception_ignore_args={$ignoreArgs}";
                $this->assertStringNotContainsString(self::SECRET, $e->getMessage(), "message ({$ctx})");
                $this->assertStringNotContainsString(self::SECRET, $e->getTraceAsString(), "getTraceAsString ({$ctx})");
                $this->assertStringNotContainsString(self::SECRET, print_r($e->getTrace(), true), "getTrace ({$ctx})");

                ob_start();
                var_dump($e);
                $dumped = (string) ob_get_clean();
                $this->assertStringNotContainsString(self::SECRET, $dumped, "var_dump(exception) ({$ctx})");
            }
        }
    }

    public function testSensitiveParameterRedactsTheRawValueFromTracesEvenWithArgsExposed(): void
    {
        // Mirror of Credential's own constructor/factory signature: a #[\SensitiveParameter] string
        // arg is redacted from stack-trace argument dumps even when zend.exception_ignore_args=0.
        $sensitiveThenThrow = static function (#[\SensitiveParameter] string $raw): never {
            throw new \RuntimeException('boom while holding a raw secret');
        };

        foreach (['0', '1'] as $ignoreArgs) {
            ini_set('zend.exception_ignore_args', $ignoreArgs);

            try {
                $sensitiveThenThrow(self::SECRET);
                $this->fail('the callable must throw.');
            } catch (\RuntimeException $e) {
                $ctx = "zend.exception_ignore_args={$ignoreArgs}";
                $this->assertStringNotContainsString(self::SECRET, $e->getTraceAsString(), "getTraceAsString ({$ctx})");
                $this->assertStringNotContainsString(self::SECRET, print_r($e->getTrace(), true), "getTrace ({$ctx})");
            }
        }
    }

    // ---------------------------------------------------------------- KNOWN LEAKS (documented boundary)

    /**
     * DOCUMENTED RESIDUAL LEAK, pending Rod's final call — NOT an endorsement.
     *
     * `var_export()` and the `(array)` cast read an object's raw private properties directly and
     * bypass `__debugInfo()`, so under the pure private-property idiom (no closure, no WeakMap) they
     * DO surface the secret. Sealing them is impossible without holding the value outside the object —
     * the exact machinery the design deliberately rejected. This test pins that reality so the
     * limitation is version-controlled: if a future change seals these surfaces, this test fails and
     * forces the report/README note to be updated. The rule stands: never `var_export()` or
     * `(array)`-cast a Credential.
     */
    public function testVarExportAndArrayCastAreTheKnownResidualLeaksOfTheNoMagicIdiom(): void
    {
        $cred = Credential::bearer(self::SECRET);

        // Documented leak: var_export dumps the private property in cleartext.
        $this->assertStringContainsString(self::SECRET, var_export($cred, true));

        // Documented leak: the (array) cast exposes the private property under a mangled key.
        $arr = (array) $cred;
        $mangled = "\0" . Credential::class . "\0value";
        $this->assertArrayHasKey($mangled, $arr);
        $this->assertSame(self::SECRET, $arr[$mangled]);
    }

    // ---------------------------------------------------------------- helpers

    private function throwWhileHolding(Credential $credential): void
    {
        // $credential is an argument on this frame. Even with args exposed in traces, an object arg is
        // rendered as Object(Milpa\Auth\Credential) — never expanded to its private value.
        throw new \RuntimeException('credential verification failed');
    }
}
