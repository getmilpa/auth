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

use Milpa\Auth\WebAuthn\Cbor;
use PHPUnit\Framework\TestCase;

/** The minimal CBOR decoder, across every major type it supports and every shape it refuses. */
final class CborTest extends TestCase
{
    /**
     * @dataProvider vectors
     *
     * @param mixed $expected
     */
    public function testItDecodesTheSupportedMajorTypes(string $hex, $expected): void
    {
        self::assertSame($expected, Cbor::decode(hex2bin($hex)));
    }

    /** @return iterable<string, array{0: string, 1: mixed}> */
    public static function vectors(): iterable
    {
        yield 'small uint' => ['0a', 10];
        yield '1-byte uint' => ['1830', 48];
        yield '2-byte uint' => ['190100', 256];
        yield '4-byte uint' => ['1a00010000', 65536];
        yield 'negative small' => ['26', -7];           // ES256's alg
        yield '1-byte negative' => ['3818', -25];
        yield 'byte string' => ['43010203', "\x01\x02\x03"];
        yield 'text string' => ['63666d74', 'fmt'];
        yield 'array' => ['83010203', [1, 2, 3]];
        yield 'map int keys' => ['a201020304', [1 => 2, 3 => 4]];
    }

    public function testAnEightByteLengthDecodes(): void
    {
        // major 0, minor 27 (8-byte argument) = 1.
        self::assertSame(1, Cbor::decode(hex2bin('1b0000000000000001')));
    }

    public function testTrailingBytesAreRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        Cbor::decode(hex2bin('0a0a')); // two items where one is expected
    }

    public function testTruncatedInputIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        Cbor::decode(hex2bin('43ffff')); // says 3 bytes, gives 2
    }

    public function testAnEmptyInputIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        Cbor::decode('');
    }

    public function testAnUnsupportedMajorTypeIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        Cbor::decode(hex2bin('e0')); // major type 7 (simple/float)
    }

    public function testAnUnsupportedLengthEncodingIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        Cbor::decode(hex2bin('1c')); // minor 28 is reserved
    }

    public function testAMapKeyThatIsNeitherIntNorStringIsRefused(): void
    {
        $this->expectException(\RuntimeException::class);
        // map with one pair whose key is an array ([] -> 0x80): a1 80 00
        Cbor::decode(hex2bin('a18000'));
    }
}
