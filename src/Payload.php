<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */

namespace HyperfExt\Jwt;

use Hyperf\Collection\Arr;
use Hyperf\Context\ApplicationContext;
use Hyperf\Contract\Arrayable;
use Hyperf\Contract\Jsonable;
use HyperfExt\Jwt\Claims\AbstractClaim;
use HyperfExt\Jwt\Claims\Collection;
use HyperfExt\Jwt\Contracts\PayloadValidatorInterface;
use HyperfExt\Jwt\Exceptions\PayloadException;

use function Hyperf\Support\value;

class Payload implements \ArrayAccess, Arrayable, \Countable, Jsonable, \JsonSerializable
{
    /**
     * The collection of claims.
     *
     * @var Collection
     */
    private $claims;

    /**
     * @var PayloadValidatorInterface
     */
    private $validator;

    /**
     * Build the Payload.
     */
    public function __construct(Collection $claims, bool $ignoreExpired = false)
    {
        $this->validator = ApplicationContext::getContainer()->get(PayloadValidatorInterface::class);
        $this->claims = $this->validator->check($claims, $ignoreExpired);
    }

    /**
     * Get the payload as a string.
     */
    public function __toString(): string
    {
        return $this->toJson();
    }

    /**
     * Invoke the Payload as a callable function.
     *
     * @param mixed $claim
     *
     * @return mixed
     */
    public function __invoke($claim = null)
    {
        return $this->get($claim);
    }

    /**
     * Magically get a claim value.
     *
     * @return mixed
     * @throws \BadMethodCallException
     */
    public function __call(string $method, array $parameters)
    {
        if (preg_match('/get(.+)\b/i', $method, $matches)) {
            foreach ($this->claims as $claim) {
                if (get_class($claim) === 'HyperfExt\\Jwt\\Claims\\' . $matches[1]) {
                    return $claim->getValue();
                }
            }
        }

        throw new \BadMethodCallException(sprintf('The claim [%s] does not exist on the payload.', $method));
    }

    /**
     * Get the array of claim instances.
     */
    public function getClaims(): Collection
    {
        return $this->claims;
    }

    /**
     * Checks if a payload matches some expected values.
     */
    public function matches(array $values, bool $strict = false): bool
    {
        if (empty($values)) {
            return false;
        }

        $claims = $this->getClaims();

        foreach ($values as $key => $value) {
            if (! $claims->has($key) or ! $claims->get($key)->matches($value, $strict)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if a payload strictly matches some expected values.
     */
    public function matchesStrict(array $values): bool
    {
        return $this->matches($values, true);
    }

    /**
     * Get the payload.
     *
     * @param mixed $claim
     *
     * @return mixed
     */
    public function get($claim = null)
    {
        $claim = value($claim);

        if ($claim !== null) {
            if (is_array($claim)) {
                return array_map([$this, 'get'], $claim);
            }

            return Arr::get($this->toArray(), $claim);
        }

        return $this->toArray();
    }

    /**
     * Get the underlying Claim instance.
     */
    public function getInternal(string $claim): AbstractClaim
    {
        return $this->claims->getByClaimName($claim);
    }

    /**
     * Determine whether the payload has the claim (by instance).
     */
    public function has(AbstractClaim $claim): bool
    {
        return $this->claims->has($claim->getName());
    }

    /**
     * Determine whether the payload has the claim (by key).
     */
    public function hasKey(string $claim): bool
    {
        return $this->offsetExists($claim);
    }

    /**
     * Get the array of claims.
     */
    public function toArray(): array
    {
        return $this->claims->toPlainArray();
    }

    /**
     * Convert the object into something JSON serializable.
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Get the payload as JSON.
     */
    public function toJson(int $options = JSON_UNESCAPED_SLASHES): string
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Determine if an item exists at an offset.
     *
     * @param mixed $key
     */
    public function offsetExists($key): bool
    {
        return Arr::has($this->toArray(), $key);
    }

    /**
     * Get an item at a given offset.
     *
     * @param mixed $key
     */
    public function offsetGet($key): mixed
    {
        return Arr::get($this->toArray(), $key);
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @throws PayloadException
     */
    public function offsetSet(mixed $key, mixed $value): void
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Don't allow changing the payload as it should be immutable.
     *
     * @param string $key
     *
     * @throws PayloadException
     */
    public function offsetUnset(mixed $key): void
    {
        throw new PayloadException('The payload is immutable');
    }

    /**
     * Count the number of claims.
     */
    public function count(): int
    {
        return count($this->toArray());
    }
}
