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

namespace Milpa\Auth\Http;

use Milpa\Auth\Exceptions\CsrfDeniedException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 double-submit CSRF guard — the CRM's `OAuthStateGuard` generalized into the pipeline. A
 * state token is issued into an httpOnly, `SameSite=Lax` cookie and must be echoed back on every
 * state-changing request, in the configured form field or header. The guard compares the two
 * timing-safe with {@see hash_equals()} and refuses (403 {@see CsrfDeniedException}) on any mismatch
 * or absence. Safe, side-effect-free methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) are not checked.
 *
 * It reads everything from the PSR-7 request — {@see ServerRequestInterface::getCookieParams()} for
 * the issued token, the header or parsed body for the submitted one — so it is fully testable without
 * real cookies. It issues no cookie itself: minting and setting the state cookie is the host's job;
 * this guard only verifies. Neither token value is ever echoed into the denial.
 */
final class CsrfGuard implements MiddlewareInterface
{
    /** @var list<string> the methods that carry no state change and are exempt from the check */
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

    /**
     * @param string $cookieName the cookie the issued state token lives in
     * @param string $field      the form field / header name the request echoes the token back in
     */
    public function __construct(
        private readonly string $cookieName,
        private readonly string $field,
    ) {
    }

    /**
     * Verifies the double-submit state token on a state-changing request and passes it on, or throws
     * {@see CsrfDeniedException} (403) when the submitted token is absent or does not match. Safe
     * methods pass through unchecked.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($this->isStateChanging($request) && !$this->matches($this->issuedToken($request), $this->submittedToken($request))) {
            throw CsrfDeniedException::stateMismatch();
        }

        return $handler->handle($request);
    }

    /**
     * Whether `$request`'s method changes state and must therefore carry a valid state token.
     */
    private function isStateChanging(ServerRequestInterface $request): bool
    {
        return !in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, true);
    }

    /**
     * The state token issued into the state cookie, or `null` when the cookie is absent or blank.
     */
    private function issuedToken(ServerRequestInterface $request): ?string
    {
        $value = $request->getCookieParams()[$this->cookieName] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * The state token the request echoes back — the configured header first, then the parsed body
     * field — or `null` when neither carries a non-empty value.
     */
    private function submittedToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine($this->field);
        if ($header !== '') {
            return $header;
        }

        $body = $request->getParsedBody();
        if (is_array($body) && isset($body[$this->field]) && is_string($body[$this->field]) && $body[$this->field] !== '') {
            return $body[$this->field];
        }

        return null;
    }

    /**
     * A timing-safe comparison of the issued and submitted tokens — false (never a leak) when either
     * is absent, otherwise {@see hash_equals()}.
     */
    private function matches(?string $issued, ?string $submitted): bool
    {
        if ($issued === null || $submitted === null) {
            return false;
        }

        return hash_equals($issued, $submitted);
    }
}
