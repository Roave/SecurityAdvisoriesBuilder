<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class Version
{
    const STABILITY_TAIL = '[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)*+)?)?([.-]?dev)?';
    const VALIDITY_MATCHER = '/^(?:\d+\.)*\d+'.self::STABILITY_TAIL.'$/';

    /**
     * @var string
     */
    private $version;

    /**
     * @param string $version
     */
    private function __construct(string $version)
    {
        $this->version = $version;
    }

    /**
     * @param string $version
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $version) : self
    {
        if (! preg_match(self::VALIDITY_MATCHER, $version)) {
            throw new \InvalidArgumentException(sprintf('Given version "%s" is not a valid version string', $version));
        }

        return new self($version);
    }

    public function equalTo(self $other) : bool
    {
        return (bool) version_compare($this->stripEndZeroes(), $other->stripEndZeroes(), '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        return (bool) version_compare($this->version, $other->version, '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        return (bool) version_compare($this->version, $other->version, '>=');
    }

    public function stripEndZeroes() : string
    {
        return preg_replace('/\.[\.0+]+$/', '', (string)$this->version);
    }
}
