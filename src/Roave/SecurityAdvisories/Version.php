<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Composer\Semver\VersionParser;

final class Version
{
    private const STABILITY_TAIL =  '[._-]?'.
                                    '(?:(stable|beta|rc|alpha|patch)((?:[.-]?\d+)+)?)?'.
                                    '([.-]?dev)?';

    private const VALIDITY_MATCHER = '/^(?:\d+\.)*\d+'.self::STABILITY_TAIL.'$/';

    /**
     * @var string
     */
    private $version;

    /**
     * @var VersionParser
     */
    private static $versionParser;

    /**
     * @param string $version
     */
    private function __construct(string $version)
    {
        if (self::$versionParser == null) {
            self::$versionParser = new VersionParser();
        }

        $this->version = $version;
    }

    /**
     * @param string $version
     *
     * @return self
     *
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
        return version_compare(self::$versionParser->normalize($this->toString()), self::$versionParser->normalize($other->toString()), '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        return version_compare(self::$versionParser->normalize($this->toString()), self::$versionParser->normalize($other->toString()), '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        return version_compare(self::$versionParser->normalize($this->toString()), self::$versionParser->normalize($other->toString()), '>=');
    }

    public function toString()
    {
        return $this->version;
    }

}
