<?php

declare(strict_types=1);
/**
 * This file is part of hyperf-ext/jwt
 *
 * @link     https://github.com/hyperf-ext/jwt
 * @contact  eric@zhu.email
 * @license  https://github.com/hyperf-ext/jwt/blob/master/LICENSE
 */

namespace HyperfTest;

use HyperfExt\Jwt\Blacklist;
use HyperfExt\Jwt\Claims\Collection;
use HyperfExt\Jwt\Claims\Expiration;
use HyperfExt\Jwt\Claims\IssuedAt;
use HyperfExt\Jwt\Claims\Issuer;
use HyperfExt\Jwt\Claims\JwtId;
use HyperfExt\Jwt\Claims\NotBefore;
use HyperfExt\Jwt\Claims\Subject;
use HyperfExt\Jwt\Contracts\StorageInterface;
use HyperfExt\Jwt\Payload;

/**
 * @internal
 * @coversNothing
 */
class BlacklistTest extends AbstractTestCase
{
    /**
     * @var \HyperfExt\Jwt\Contracts\StorageInterface|\Mockery\MockInterface
     */
    protected $storage;

    /**
     * @var Blacklist
     */
    protected $blacklist;

    public function setUp(): void
    {
        parent::setUp();

        $this->storage = \Mockery::mock(StorageInterface::class);
        $this->blacklist = new Blacklist($this->storage, 0, 3600 * 24 * 14);
    }

    /** @test */
    public function itShouldAddAValidTokenToTheBlacklist(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];

        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $refreshTtl = 1209660;

        $this->storage->expects('get')
            ->with('foo')
            ->andReturns([]);

        $this->storage->expects('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTtl + 60);

        $this->assertTrue($this->blacklist->setRefreshTtl($refreshTtl)->add($payload));
    }

    /** @test */
    public function itShouldAddATokenWithNoExpToTheBlacklistForever(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('forever')->with('foo', 'forever');

        $this->assertTrue($this->blacklist->add($payload));
    }

    /** @test */
    public function itShouldReturnTrueWhenAddingAnExpiredTokenToTheBlacklist(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection, true);

        $refreshTtl = 1209660;

        $this->storage->expects('get')
            ->with('foo')
            ->andReturns([]);

        $this->storage->expects('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTtl + 60);

        $this->assertTrue($this->blacklist->setRefreshTtl($refreshTtl)->add($payload));
    }

    /** @test */
    public function itShouldReturnTrueEarlyWhenAddingAnItemAndItAlreadyExists(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp - 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foo'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection, true);

        $refreshTtl = 1209660;

        $this->storage->expects('get')
            ->with('foo')
            ->andReturns(['valid_until' => $this->testNowTimestamp]);

        $this->storage->allows('add')
            ->with('foo', ['valid_until' => $this->testNowTimestamp], $refreshTtl + 60)
            ->never();

        $this->assertTrue($this->blacklist->setRefreshTtl($refreshTtl)->add($payload));
    }

    /** @test */
    public function itShouldCheckWhetherATokenHasBeenBlacklisted()
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];

        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('get')->with('foobar')->andReturns(['valid_until' => $this->testNowTimestamp]);

        $this->assertTrue($this->blacklist->has($payload));
    }

    public static function blacklist_provider(): array
    {
        return [
            [null],
            [0],
            [''],
            [[]],
            [['valid_until' => strtotime('+1day')]],
        ];
    }

    /**
     * @test
     * @dataProvider blacklist_provider
     */
    public function itShouldCheckWhetherATokenHasNotBeenBlacklisted(mixed $result): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];

        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('get')->with('foobar')->andReturns($result);
        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function itShouldCheckWhetherATokenHasBeenBlacklistedForever(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('get')->with('foobar')->andReturns('forever');

        $this->assertTrue($this->blacklist->has($payload));
    }

    /** @test */
    public function itShouldCheckWhetherATokenHasBeenBlacklistedWhenTheTokenIsNotBlacklisted(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('get')->with('foobar')->andReturns(null);

        $this->assertFalse($this->blacklist->has($payload));
    }

    /** @test */
    public function itShouldRemoveATokenFromTheBlacklist(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->allows('destroy')->with('foobar')->andReturns(true);
        $this->assertTrue($this->blacklist->remove($payload));
    }

    /** @test */
    public function itShouldSetACustomUniqueKeyForTheBlacklist(): void
    {
        $claims = [
            new Subject(1),
            new Issuer('http://example.com'),
            new Expiration($this->testNowTimestamp + 3600),
            new NotBefore($this->testNowTimestamp),
            new IssuedAt($this->testNowTimestamp),
            new JwtId('foobar'),
        ];
        $collection = Collection::make($claims);

        $payload = new Payload($collection);

        $this->storage->expects('get')->with(1)->andReturns(['valid_until' => $this->testNowTimestamp]);

        $this->assertTrue($this->blacklist->setKey('sub')->has($payload));
        $this->assertSame(1, $this->blacklist->getKey($payload));
    }

    /** @test */
    public function itShouldEmptyTheBlacklist()
    {
        $this->storage->allows('flush');
        $this->assertTrue($this->blacklist->clear());
    }

    /** @test */
    public function itShouldSetAndGetTheBlacklistGracePeriod(): void
    {
        $this->assertInstanceOf(Blacklist::class, $this->blacklist->setGracePeriod(15));
        $this->assertSame(15, $this->blacklist->getGracePeriod());
    }

    /** @test */
    public function itShouldSetAndGetTheBlacklistRefreshTtl(): void
    {
        $this->assertInstanceOf(Blacklist::class, $this->blacklist->setRefreshTtl(15));
        $this->assertSame(15, $this->blacklist->getRefreshTtl());
    }
}
