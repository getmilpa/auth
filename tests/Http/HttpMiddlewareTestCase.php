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

namespace Milpa\Auth\Tests\Http;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Shared PSR-15 scaffolding for the middleware suite. It builds a {@see ServerRequestInterface}
 * double whose `withAttribute()` genuinely round-trips (so a downstream handler can read back what a
 * middleware attached) and a capturing {@see RequestHandlerInterface} spy — enough to exercise the
 * pipeline without pulling a real PSR-7 implementation into this leaf package's test deps.
 */
abstract class HttpMiddlewareTestCase extends TestCase
{
    /**
     * A configured PSR-7 server-request double.
     *
     * @param array{
     *     headers?: array<string, string>,
     *     cookies?: array<string, mixed>,
     *     parsedBody?: mixed,
     *     method?: string,
     *     attributes?: array<string, mixed>
     * } $opts
     */
    protected function request(array $opts = []): ServerRequestInterface
    {
        $headers = $opts['headers'] ?? [];
        $cookies = $opts['cookies'] ?? [];
        $parsedBody = $opts['parsedBody'] ?? null;
        $method = $opts['method'] ?? 'GET';
        $attributes = $opts['attributes'] ?? [];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->method('getHeaderLine')->willReturnCallback(
            static fn (string $name): string => (string) ($headers[$name] ?? '')
        );
        $request->method('getCookieParams')->willReturn($cookies);
        $request->method('getParsedBody')->willReturn($parsedBody);
        $request->method('getMethod')->willReturn($method);
        $request->method('getAttribute')->willReturnCallback(
            static fn (string $name, mixed $default = null): mixed => $attributes[$name] ?? $default
        );
        $request->method('withAttribute')->willReturnCallback(
            function (string $name, mixed $value) use ($headers, $cookies, $parsedBody, $method, $attributes): ServerRequestInterface {
                $next = $attributes;
                $next[$name] = $value;

                return $this->request([
                    'headers' => $headers,
                    'cookies' => $cookies,
                    'parsedBody' => $parsedBody,
                    'method' => $method,
                    'attributes' => $next,
                ]);
            }
        );

        return $request;
    }

    /**
     * A handler spy that records the request it received and returns `$response`.
     */
    protected function handler(ResponseInterface $response): RequestHandlerInterface
    {
        return new class ($response) implements RequestHandlerInterface {
            public ?ServerRequestInterface $received = null;

            public function __construct(private readonly ResponseInterface $response)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->received = $request;

                return $this->response;
            }
        };
    }
}
