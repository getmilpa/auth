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
 * The base of every auth denial the middlewares raise — a fail-closed refusal that is meant to be
 * *read* by whoever hit it. Each subclass carries three things beyond an ordinary exception: an HTTP
 * {@see self::statusCode()} so a host/projector can map it without a lookup table, a stable machine
 * {@see self::errorCode()} (a `MILPA_*` string) to switch on, and a message written to teach — what
 * went wrong, how to fix it, and a link to the concept it violated. The message NEVER contains the
 * credential or token that triggered the denial: the whole point of this package is that a secret
 * never reaches a log or an error, and an error class is no exception.
 */
abstract class AuthException extends \RuntimeException
{
    /**
     * The Academy lesson every auth denial points at — the "explicit policies" fundamentals. It may
     * 404 until that lesson ships; the link is the durable target, not a promise it resolves today.
     */
    public const ACADEMY_LINK = 'https://academy.milpa.lat/learn/fundamentos/politicas-explicitas';

    /**
     * @param string $message    the learnable message — why + fix + Academy link, never a secret
     * @param int    $statusCode the HTTP status this denial maps to (401 or 403)
     * @param string $errorCode  the stable `MILPA_*` machine code for this denial
     */
    protected function __construct(
        string $message,
        private readonly int $statusCode,
        private readonly string $errorCode,
    ) {
        parent::__construct($message);
    }

    public function statusCode(): int
    {
        return $this->statusCode;
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }
}
