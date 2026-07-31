<?php

/**
 * This file is part of Milpa Auth — the identity floor of the Milpa PHP framework.
 *
 * (c) Rodrigo Vicente - TeamX Agency — https://teamx.agency <hola@teamx.agency>
 *
 * @license Apache-2.0
 *
 * @link    https://github.com/getmilpa/auth
 */

declare(strict_types=1);

namespace Milpa\Auth\Tests\Http;

use Milpa\Auth\Actor;
use Milpa\Auth\ActorType;
use Milpa\Auth\ArrayPermissionCatalog;
use Milpa\Auth\AuthContext;
use Milpa\Auth\CatalogPermissionResolver;
use Milpa\Auth\Contracts\AuthContextFactory;
use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\Contracts\PermissionResolver;
use Milpa\Auth\Exceptions\AuthMiddlewareNotInstalledException;
use Milpa\Auth\Http\AuthenticateMiddleware;
use Milpa\Auth\Http\AuthOperationHttpPolicy;
use Milpa\Command\Operation;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * La política de identidad para una operación servida por HTTP.
 *
 * Vino de `milpa/skeleton`, pasó por `milpa/admin` y aterrizó aquí, que es donde debía estar: usa
 * `milpa/auth` de arriba a abajo y no usa nada del panel. Tenerla allá obligaba a instalar
 * diecinueve paquetes para servir una operación protegida.
 *
 * Se prueba DIRECTO y no a través de un proyector: lo que esta clase decide es si la petición pasa,
 * y meter el proyector en medio mediría dos cosas a la vez. La integración con `HttpProjector` la
 * cubren `milpa/console` y la plantilla del framework.
 */
final class AuthOperationHttpPolicyTest extends TestCase
{
    private function policy(ContainerInterface $container): AuthOperationHttpPolicy
    {
        $psr17 = new Psr17Factory();

        return new AuthOperationHttpPolicy($container, $psr17, $psr17);
    }

    /** @param array<string, object> $servicios */
    private function container(array $servicios): ContainerInterface
    {
        return new class ($servicios) implements ContainerInterface {
            /** @param array<string, object> $servicios */
            public function __construct(private readonly array $servicios)
            {
            }

            public function get(string $id): ?object
            {
                return $this->servicios[$id] ?? null;
            }

            public function has(string $id): bool
            {
                return isset($this->servicios[$id]);
            }
        };
    }

    /** Un contenedor con cadena de autenticación cableada. */
    private function conCadena(): ContainerInterface
    {
        return $this->container([CredentialVerifier::class => new \stdClass()]);
    }

    private function scoped(): Operation
    {
        return new Operation(
            name: 'read_secret',
            description: 'Read a secret',
            handler: static fn (array $i): array => ['secret' => 'ok'],
            inputSchema: ['type' => 'object'],
            scopes: ['posts:read'],
        );
    }

    private function conActor(ServerRequest $request, Actor $actor): ServerRequest
    {
        return $request->withAttribute(AuthenticateMiddleware::ATTRIBUTE, AuthContext::authenticated($actor));
    }

    /** Quien tiene el scope pasa: la política contesta `null`, que significa adelante. */
    public function testAnActorHoldingTheScopeIsLetThrough(): void
    {
        $peticion = $this->conActor(new ServerRequest('GET', '/secret'), new Actor('user:42', ActorType::User, ['posts:read']));

        self::assertNull($this->policy($this->conCadena())->enforce($this->scoped(), $peticion));
    }

    /** Quien no lo tiene recibe un 403 ya formado, con el código que lo nombra. */
    public function testAnActorLackingTheScopeGetsAFormedRefusal(): void
    {
        $peticion = $this->conActor(new ServerRequest('GET', '/secret'), new Actor('user:9', ActorType::User, ['posts:write']));

        $respuesta = $this->policy($this->conCadena())->enforce($this->scoped(), $peticion);

        self::assertNotNull($respuesta);
        self::assertSame(403, $respuesta->getStatusCode());
        /** @var array{code: string} $cuerpo */
        $cuerpo = json_decode((string) $respuesta->getBody(), true);
        self::assertSame('MILPA_SCOPE_DENIED', $cuerpo['code']);
    }

    /** Sin actor verificado es 401 y no 403: no es que no pueda, es que no sabemos quién es. */
    public function testNoVerifiedActorIs401AndNot403(): void
    {
        $respuesta = $this->policy($this->conCadena())->enforce($this->scoped(), new ServerRequest('GET', '/secret'));

        self::assertNotNull($respuesta);
        self::assertSame(401, $respuesta->getStatusCode());
        /** @var array{code: string} $cuerpo */
        $cuerpo = json_decode((string) $respuesta->getBody(), true);
        self::assertSame('MILPA_AUTH_CONTEXT_MISSING', $cuerpo['code']);
    }

    /**
     * Sin cadena cableada es un 500, NUNCA un 4xx — la distinción de Rod.
     *
     * Quien llama está perfecto: autenticado y con el scope. El defecto es del host, que declaró una
     * operación protegida y no cableó con qué protegerla.
     */
    public function testNoAuthChainIsAServerErrorAndNotTheCallersFault(): void
    {
        $peticion = $this->conActor(new ServerRequest('GET', '/secret'), new Actor('user:42', ActorType::User, ['posts:read']));

        try {
            $this->policy($this->container([]))->enforce($this->scoped(), $peticion);
            self::fail('debería haber lanzado AuthMiddlewareNotInstalledException');
        } catch (AuthMiddlewareNotInstalledException $e) {
            self::assertSame(500, $e->statusCode());
            self::assertSame('MILPA_AUTH_MIDDLEWARE_NOT_INSTALLED', $e->errorCode());
            self::assertStringContainsString('read_secret', $e->getMessage());
        }
    }

    /** Una operación sin scopes ni permiso no toca nada de esto. */
    public function testAnUnprotectedOperationIsUntouched(): void
    {
        $libre = new Operation('ping', 'Ping', static fn (array $i): array => ['pong' => true], inputSchema: ['type' => 'object']);

        self::assertNull($this->policy($this->container([]))->enforce($libre, new ServerRequest('GET', '/ping')));
    }

    /** La contraparte tipada por PERMISO: concedido pasa, negado es 403 con su propio código. */
    public function testThePermissionPathGrantsAndDenies(): void
    {
        $resolver = new CatalogPermissionResolver(
            ArrayPermissionCatalog::fromArray(['roles' => ['editor' => ['permissions' => ['crm.contact:update']]]]),
        );
        $container = $this->container([
            CredentialVerifier::class => new \stdClass(),
            PermissionResolver::class => $resolver,
        ]);
        $op = new Operation(
            name: 'update_contact',
            description: 'Update a contact',
            handler: static fn (array $i): array => ['updated' => true],
            inputSchema: ['type' => 'object'],
            permission: 'crm.contact:update',
        );

        $concedido = $this->conActor(new ServerRequest('POST', '/contact'), new Actor('user:1', ActorType::User, [], [], ['editor']));
        self::assertNull($this->policy($container)->enforce($op, $concedido));

        $negado = $this->conActor(new ServerRequest('POST', '/contact'), new Actor('user:9', ActorType::User));
        $respuesta = $this->policy($container)->enforce($op, $negado);
        self::assertNotNull($respuesta);
        self::assertSame(403, $respuesta->getStatusCode());
        /** @var array{code: string} $cuerpo */
        $cuerpo = json_decode((string) $respuesta->getBody(), true);
        self::assertSame('MILPA_PERMISSION_DENIED', $cuerpo['code']);
    }

    /**
     * Un contenedor que resuelve `AuthContextFactory` en vez de `CredentialVerifier` también cuenta
     * como cadena cableada.
     *
     * Son dos formas de la misma capacidad —producir un contexto verificado— y exigir una en
     * particular convertiría un host legítimo en un 500.
     */
    public function testEitherHalfOfTheChainCounts(): void
    {
        $container = $this->container([AuthContextFactory::class => new \stdClass()]);
        $peticion = $this->conActor(new ServerRequest('GET', '/secret'), new Actor('user:42', ActorType::User, ['posts:read']));

        self::assertNull($this->policy($container)->enforce($this->scoped(), $peticion));
    }
}
