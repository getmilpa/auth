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
 * The 401 signal that {@see \Milpa\Auth\Http\RequireScopeMiddleware} had no *authenticated* actor to
 * authorize — the two ways that happens are distinct, so this carries two named constructors with two
 * machine codes. {@see self::notAttached()} means nothing populated the request's auth attribute (the
 * pipeline is wired wrong — no authenticate/session middleware ran first); {@see self::unauthenticated()}
 * means one did, but the request is anonymous or its credential was rejected. Both are 401, both
 * fail-closed, and neither message names the credential.
 */
final class AuthContextMissingException extends AuthException
{
    /**
     * The request carried no auth context at all — RequireScope ran before anything produced one.
     */
    public static function notAttached(): self
    {
        return new self(
            '[MILPA_AUTH_CONTEXT_MISSING] No auth context on this request. RequireScope authorizes a '
            . 'verified AuthContext, but nothing put one on the request. Add AuthenticateMiddleware (or '
            . 'StartSession) to the pipeline BEFORE RequireScope so a context — even an anonymous one — '
            . 'is always present. Why Milpa fails closed on a missing context: ' . self::ACADEMY_LINK,
            401,
            'MILPA_AUTH_CONTEXT_MISSING',
        );
    }

    /**
     * The request has a context but is not authenticated — anonymous, or its credential was rejected.
     */
    public static function unauthenticated(): self
    {
        return new self(
            '[MILPA_UNAUTHENTICATED] This request is not authenticated: it presented no valid credential '
            . '(the context is anonymous, or the credential it presented was rejected). Present a valid '
            . 'credential — a Bearer token or a live session — before calling a scope-protected route. '
            . 'Why Milpa fails closed on an unauthenticated request: ' . self::ACADEMY_LINK,
            401,
            'MILPA_UNAUTHENTICATED',
        );
    }
}
