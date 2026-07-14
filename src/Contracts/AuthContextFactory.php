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

use Milpa\Auth\AuthContext;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Bridges a PSR-7 request to the producer: extracts whatever credential a request carries (a Bearer
 * header, a session cookie) and resolves it to an {@see AuthContext}. It is the HTTP entry point an
 * authentication middleware calls once per request — the thing that lets a route stop trusting the
 * transport and start trusting a verified context. Fail-closed: a request with no credential
 * resolves to {@see AuthContext::anonymous()}, a bad one to {@see AuthContext::invalid()}.
 */
interface AuthContextFactory
{
    /**
     * Reads whatever credential `$request` carries and resolves it to an {@see AuthContext} —
     * anonymous when none is present, invalid when one is present but rejected.
     */
    public function fromRequest(ServerRequestInterface $request): AuthContext;
}
