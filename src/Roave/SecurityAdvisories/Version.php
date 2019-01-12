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

        return new self(self::stripEndZeroes($version));
    }

    public function equalTo(self $other) : bool
    {
        return (bool) version_compare((string)$this, (string) $other, '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        return (bool) version_compare((string)$this, (string) $other, '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        return (bool) version_compare((string)$this, (string) $other, '>=');
    }

    public static function stripEndZeroes(string $version) : string
    {
        return preg_replace('/\.[\.0+]+$/', '', $version);
    }

    public function __toString()
    {
        return $this->version;
    }
}
