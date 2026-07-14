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

use Milpa\Auth\PermissionContext;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Builds the request-scoping {@see PermissionContext} from a PSR-7 request — tenant from host/session,
 * resource from the route. Optional: without one, the enforcement layer uses {@see PermissionContext::none()}.
 * The seam that keeps tenant conventions in the host, not the leaf.
 */
interface PermissionContextFactory
{
    /** Build a PermissionContext from a PSR-7 request. */
    public function fromRequest(ServerRequestInterface $request): PermissionContext;
}
