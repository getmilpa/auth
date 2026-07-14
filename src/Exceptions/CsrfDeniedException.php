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

namespace Milpa\Auth\Exceptions;

/**
 * The 403 signal that {@see \Milpa\Auth\Http\CsrfGuard} refused a state-changing request whose CSRF
 * state token was missing or did not match the one issued in the state cookie. The message teaches the
 * fix without ever echoing either token value back — printing the expected or submitted state would
 * hand it to exactly the log an attacker reads.
 */
final class CsrfDeniedException extends AuthException
{
    /**
     * The submitted state token was absent, or did not match the issued state cookie (timing-safe).
     */
    public static function stateMismatch(): self
    {
        return new self(
            '[MILPA_CSRF_DENIED] CSRF check failed: the request state token was missing or did not match '
            . 'the one issued in the state cookie. Echo the exact token from the state cookie in the '
            . 'configured field or header on every state-changing request. Why Milpa verifies state '
            . 'tokens timing-safe: ' . self::ACADEMY_LINK,
            403,
            'MILPA_CSRF_DENIED',
        );
    }
}
