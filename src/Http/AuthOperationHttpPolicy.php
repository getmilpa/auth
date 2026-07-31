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

namespace Milpa\Auth\Http;

use Milpa\Auth\Contracts\AuthContextFactory;
use Milpa\Auth\Contracts\CredentialVerifier;
use Milpa\Auth\Contracts\PermissionContextFactory;
use Milpa\Auth\Contracts\PermissionResolver;
use Milpa\Auth\Exceptions\AuthContextMissingException;
use Milpa\Auth\Exceptions\AuthMiddlewareNotInstalledException;
use Milpa\Auth\Exceptions\PermissionDeniedException;
use Milpa\Auth\Exceptions\ScopeDeniedException;
use Milpa\Auth\AuthContext;
use Milpa\Auth\Permission;
use Milpa\Command\Operation;
use Milpa\Command\OperationHttpPolicy;
use Psr\Container\ContainerInterface;
use Milpa\ToolRuntime\Contracts\ToolContext;
use Milpa\ToolRuntime\PolicyGate;
use Milpa\ToolRuntime\ToolDefinition;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * La política de la superficie HTTP con `milpa/auth`: qué exige una operación antes de correr.
 *
 * Es la implementación de {@see OperationHttpPolicy} que usa identidad de verdad: contexto
 * verificado, scopes, permisos. El proyector que la consume no conoce nada de esto — exponer una
 * operación por HTTP no obliga a instalar un sistema de autenticación, y exigir identidad no obliga
 * a instalar un proyector.
 *
 * ── POR QUÉ TERMINÓ AQUÍ ────────────────────────────────────────────────────────────────────────
 *
 * Vino de `milpa/skeleton` cuando éste se retiró como puerta de entrada (P14.3), pasó por
 * `milpa/admin` —que ya requería identidad— y aterrizó donde debía estar desde el principio: usa
 * `milpa/auth` de arriba a abajo, así que vive en `milpa/auth`. Ponerla en el panel obligaba a
 * instalar diecinueve paquetes para servir una operación protegida por HTTP.
 *
 * Scope Y permission: una operación se tipa por uno o por el otro, nunca por los dos — `Operation` lo
 * rechaza en su constructor. El `PolicyGate` de tool-runtime es defensa en profundidad específica de
 * scope y no aplica a las tipadas por permiso.
 */
class AuthOperationHttpPolicy implements OperationHttpPolicy
{
    /**
     * El contenedor se pide como PSR-11 y no como el de la familia: este paquete es piso y lo único
     * que hace con él es `has()`/`get()`. Pedir `DIContainerInterface` lo ataría a `milpa/core` por
     * una capacidad que el estándar ya cubre — y el contenedor de la familia lo satisface, porque
     * extiende PSR-11.
     *
     * Las fábricas PSR-17 también se inyectan, por lo mismo: no le elige a nadie su implementación de
     * PSR-7. Quien monta la app ya tiene una.
     */
    public function __construct(
        private readonly ContainerInterface $container,
        private readonly ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
    ) {
    }

    /**
     * `null` cuando la petición pasa; un 401/403 ya formado cuando `milpa/auth` la niega.
     *
     * Lanza {@see AuthMiddlewareNotInstalledException} (500) cuando la operación exige identidad y el
     * host no cableó una cadena de autenticación: es la distinción de Rod, y es un error de servidor.
     * Un 4xx culparía a quien llamó, que no hizo nada mal — el host declaró algo protegido y lo dejó
     * sin guardia. Se conserva la excepción de `milpa/auth` y no la de console porque ésta lleva su
     * `statusCode()` y su `errorCode()`, que es lo que un host ya mapea hoy;
     * {@see UnguardedOperationException} cubre el otro caso, el de un host sin NINGUNA política.
     */
    public function enforce(Operation $op, ServerRequestInterface $request): ?ResponseInterface
    {
        if ($op->permission !== null) {
            return $this->enforcePermission($op, $request);
        }

        if ($op->scopes !== []) {
            return $this->enforceScopes($op, $request);
        }

        return null;
    }

    /**
     * La compuerta de scopes, cerrada por defecto.
     *
     * `RequireScopeMiddleware` lee el {@see AuthContext} que un {@see AuthenticateMiddleware} río
     * arriba dejó en `'milpa.auth'` y lanza la negativa tipada; el handler centinela sólo corre si
     * admitió la petición.
     */
    public function enforceScopes(Operation $op, ServerRequestInterface $request): ?ResponseInterface
    {
        if (!$this->authChainInstalled()) {
            throw AuthMiddlewareNotInstalledException::forScopedOperation($op->name, $op->scopes);
        }

        $guard = new RequireScopeMiddleware(...$op->scopes);

        try {
            $guard->process($request, $this->sentinel());
        } catch (AuthContextMissingException|ScopeDeniedException $e) {
            return $this->json($e->statusCode(), ['error' => $e->getMessage(), 'code' => $e->errorCode()]);
        }

        // Autorizada. El contexto deja de mentir: el átomo pasa por la MISMA capa de política que
        // guarda MCP, con un ToolContext::web honesto (principal real, scopes reales).
        return $this->enforceWebPolicy($op, $request);
    }

    /**
     * La contraparte tipada por permiso, espejo de {@see self::enforceScopes()}.
     *
     * Corre sólo la compuerta honesta de `RequirePermission`: el `PolicyGate` de tool-runtime razona
     * sobre scopes y aplicarlo aquí sería juzgar con la vara equivocada.
     */
    public function enforcePermission(Operation $op, ServerRequestInterface $request): ?ResponseInterface
    {
        if (!$this->authChainInstalled()) {
            throw AuthMiddlewareNotInstalledException::forPermissionedOperation($op->name, (string) $op->permission);
        }

        $resolver = $this->container->has(PermissionResolver::class) ? $this->container->get(PermissionResolver::class) : null;
        $contextFactory = $this->container->has(PermissionContextFactory::class) ? $this->container->get(PermissionContextFactory::class) : null;

        $guard = new RequirePermissionMiddleware(
            Permission::parse((string) $op->permission),
            $resolver instanceof PermissionResolver ? $resolver : null,
            $contextFactory instanceof PermissionContextFactory ? $contextFactory : null,
        );

        try {
            $guard->process($request, $this->sentinel());
        } catch (AuthContextMissingException|PermissionDeniedException $e) {
            return $this->json($e->statusCode(), ['error' => $e->getMessage(), 'code' => $e->errorCode()]);
        }

        return null;
    }

    /**
     * Si el host cableó una cadena capaz de producir un {@see AuthContext} verificado.
     *
     * Cuando no hay ninguna, una operación con scopes no se puede hacer cumplir honestamente — y eso
     * es configuración del host, no una petición fallida.
     */
    public function authChainInstalled(): bool
    {
        return $this->container->has(CredentialVerifier::class)
            || $this->container->has(AuthContextFactory::class);
    }

    /**
     * Defensa en profundidad para una petición YA autorizada: reconstruye el {@see ToolContext::web()}
     * honesto y lo pasa por el mismo {@see PolicyGate} que guarda MCP. Opt-in: no hace nada si
     * `milpa/tool-runtime` no está instalado.
     */
    public function enforceWebPolicy(Operation $op, ServerRequestInterface $request): ?ResponseInterface
    {
        if (!$this->policyLayerInstalled()) {
            return null;
        }

        $context = $request->getAttribute(AuthenticateMiddleware::ATTRIBUTE);
        if (!$context instanceof AuthContext || $context->actor === null) {
            return null; // inalcanzable una vez que la compuerta de arriba admitió; red de seguridad
        }

        $decision = (new PolicyGate())->authorize(
            ToolContext::web($context->actor->id, $context->actor->scopes),
            new ToolDefinition(
                name: $op->name,
                description: $op->description,
                inputSchema: $op->inputSchema ?? [],
                callback: static fn (): null => null,
                scopes: $op->scopes,
                mutating: $op->mutating,
                requiresConfirmation: $op->requiresConfirmation,
            ),
        );

        if (!$decision->allowed) {
            return $this->json(403, ['error' => $decision->reason, 'code' => 'MILPA_SCOPE_DENIED']);
        }

        return null;
    }

    /**
     * Si la capa de política de `milpa/tool-runtime` está instalada.
     *
     * Es un método y no un `class_exists` en línea para que se pueda ejercitar el camino en que NO
     * está: es una dependencia sugerida, así que en las pruebas de este paquete siempre está —y una
     * rama que sólo corre en la instalación de alguien más es una rama que nadie probó nunca.
     */
    protected function policyLayerInstalled(): bool
    {
        return class_exists(ToolContext::class) && class_exists(PolicyGate::class);
    }

    /**
     * El handler que corre sólo si el middleware admitió la petición.
     *
     * Su 204 no viaja a ningún lado: {@see HttpProjector} sigue con la operación cuando esta política
     * devuelve `null`. Existe porque un middleware PSR-15 necesita a quién delegar para poder admitir.
     */
    private function sentinel(): RequestHandlerInterface
    {
        return new class ($this->responses) implements RequestHandlerInterface {
            public function __construct(private readonly ResponseFactoryInterface $responses)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->responses->createResponse(204);
            }
        };
    }

    private function json(int $status, mixed $data): ResponseInterface
    {
        return $this->responses->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams->createStream((string) json_encode($data)));
    }
}
