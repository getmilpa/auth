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
 * A minimal CBOR (RFC 8949) decoder — only the shapes WebAuthn attestation needs.
 *
 * WebAuthn's `attestationObject` and its embedded COSE public key are CBOR, so reading a registration
 * means reading CBOR. Rather than take a heavy dependency for a handful of major types, this decodes
 * exactly what appears there: unsigned and negative integers, byte and text strings, arrays and maps
 * (major types 0–5). Indefinite-length items, tags, floats, and simple values are NOT supported —
 * an authenticator does not emit them here, and refusing them keeps the surface small and honest.
 *
 * It is deliberately strict: anything it does not understand, or any trailing garbage, throws. A parser
 * that guesses past a malformed attestation is a security bug, not a convenience.
 */
final class Cbor
{
    /**
     * Decode one CBOR item from the head of $bytes, requiring it to consume the whole string.
     *
     * @return mixed the decoded value (int, string, list, or array-map)
     */
    public static function decode(string $bytes): mixed
    {
        $offset = 0;
        $value = self::decodeItem($bytes, $offset);
        if ($offset !== \strlen($bytes)) {
            throw new \RuntimeException('CBOR: trailing bytes after the top-level item');
        }

        return $value;
    }

    /**
     * Decode one item starting at $offset, advancing $offset past it.
     *
     * @return mixed
     */
    public static function decodeItem(string $bytes, int &$offset): mixed
    {
        if ($offset >= \strlen($bytes)) {
            throw new \RuntimeException('CBOR: unexpected end of input');
        }
        $initial = \ord($bytes[$offset]);
        $offset++;
        $major = $initial >> 5;
        $minor = $initial & 0x1f;
        $arg = self::argument($bytes, $offset, $minor);

        return match ($major) {
            0 => $arg,                                   // unsigned integer
            1 => -1 - $arg,                              // negative integer
            2 => self::take($bytes, $offset, $arg),     // byte string
            3 => self::take($bytes, $offset, $arg),     // text string (kept as raw bytes)
            4 => self::decodeArray($bytes, $offset, $arg),
            5 => self::decodeMap($bytes, $offset, $arg),
            default => throw new \RuntimeException('CBOR: unsupported major type ' . $major),
        };
    }

    private static function argument(string $bytes, int &$offset, int $minor): int
    {
        if ($minor < 24) {
            return $minor;
        }
        $len = match ($minor) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            default => throw new \RuntimeException('CBOR: unsupported length encoding ' . $minor),
        };
        $raw = self::take($bytes, $offset, $len);
        $n = 0;
        foreach (str_split($raw) as $c) {
            $n = ($n << 8) | \ord($c);
        }

        return $n;
    }

    private static function take(string $bytes, int &$offset, int $length): string
    {
        if ($length < 0 || $offset + $length > \strlen($bytes)) {
            throw new \RuntimeException('CBOR: string/length runs past end of input');
        }
        $slice = substr($bytes, $offset, $length);
        $offset += $length;

        return $slice;
    }

    /** @return list<mixed> */
    private static function decodeArray(string $bytes, int &$offset, int $count): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = self::decodeItem($bytes, $offset);
        }

        return $out;
    }

    /** @return array<int|string, mixed> */
    private static function decodeMap(string $bytes, int &$offset, int $count): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $key = self::decodeItem($bytes, $offset);
            if (!\is_int($key) && !\is_string($key)) {
                throw new \RuntimeException('CBOR: map key is neither int nor string');
            }
            $out[$key] = self::decodeItem($bytes, $offset);
        }

        return $out;
    }
}
