<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */

namespace HyperfExt\Jwt\RequestParser\Handlers;

use HyperfExt\Jwt\Contracts\RequestParser\HandlerInterface as ParserContract;
use Psr\Http\Message\ServerRequestInterface;

class InputSource implements ParserContract
{
    use KeyTrait;

    public function parse(ServerRequestInterface $request): ?string
    {
        $data = \Hyperf\Collection\data_get(
            is_array($data = $request->getParsedBody()) ? $data : [],
            $this->key
        );
        return empty($data) === null ? null : (string) $data;
    }
}
