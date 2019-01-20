<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Composer\Semver\VersionParser;

final class Version
{
    private const STABILITY_TAIL = '[._-]?'.
                           '(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?'.
                           '([.-]?dev)?';

    private const VALIDITY_MATCHER = '/^(?:\d+\.)*\d+'.self::STABILITY_TAIL.'$/';

    /**
     * @var string
     */
    private $version;
    /**
     * @var VersionParser
     */
    private $versionParser;

    /**
     * @param string $version
     * @param VersionParser $versionParser
     */
    private function __construct(string $version, VersionParser $versionParser)
    {
        $this->version = $version;
        $this->versionParser = $versionParser;
    }

    /**
     * @param string $version
     *
     * @param VersionParser $versionParser
     *
     * @return self
     *
     */
    public static function fromString(string $version, VersionParser $versionParser) : self
    {
        if (! preg_match(self::VALIDITY_MATCHER, $version)) {
            throw new \InvalidArgumentException(sprintf('Given version "%s" is not a valid version string', $version));
        }

        return new self($version, $versionParser);
    }

    public function equalTo(self $other) : bool
    {
        return version_compare($this->versionParser->normalize($this->toString()), $this->versionParser->normalize($other->toString()), '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        return version_compare($this->versionParser->normalize($this->toString()), $this->versionParser->normalize($other->toString()), '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        return version_compare($this->versionParser->normalize($this->toString()), $this->versionParser->normalize($other->toString()), '>=');
    }

    public function toString()
    {
        return $this->version;
    }

}
