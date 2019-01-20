<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Composer\Semver\VersionParser;

/**
 * A simple version, such as 1.0 or 1.0.0.0 or 2.0.1.3.2
 */
final class Boundary
{
    private const STABILITY_TAIL = '[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?([.-]?dev)?';
    private const MATCHER = '/^\s*(<|<=|=|>=|>)\s*((?:\d+\.)*\d+'.self::STABILITY_TAIL.')\s*$/';
    const VALID_ADJACENCY_MAP = [
        ['<', '='],
        ['<', '>='],
        ['<=', '>'],
        ['=', '>'],
    ];

    /**
     * @var Version
     */
    private $version;

    /**
     * @var string one of "<", "<=", "=", ">=", ">"
     */
    private $limitType;

    private function __construct(Version $version, string $limitType)
    {
        $this->version   = $version;
        $this->limitType = $limitType;
    }

    /**
     * @param string $boundary
     *
     * @return Boundary
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $boundary) : self
    {
        if (! preg_match(self::MATCHER, $boundary, $matches)) {
            throw new \InvalidArgumentException(sprintf('The given string "%s" is not a valid boundary', $boundary));
        }
        return new self(
            Version::fromString($matches[2], new VersionParser()),
            $matches[1]
        );
    }

    public function limitIncluded() : bool
    {
        return in_array($this->limitType, ['<=', '=', '>='], true);
    }

    public function adjacentTo(self $other) : bool
    {
        if (! $other->version->equalTo($this->version)) {
            return false;
        }

        return in_array([$this->limitType, $other->limitType], self::VALID_ADJACENCY_MAP, true)
            || in_array([$other->limitType, $this->limitType], self::VALID_ADJACENCY_MAP, true);
    }

    public function getVersion() : Version
    {
        return $this->version;
    }

    public function getBoundaryString() : string
    {
        return $this->limitType . $this->stripTrailingZeroes($this->version->toString());
    }

    /**
     * Strips all trailing '0' and '.' out of the version,
     * e.g. for '0.0.0' version this part will be removed - '.0.0'
     */
    private function stripTrailingZeroes(string $version) : string
    {
        return preg_replace('/\.[\.0+]+$/', '', $version);
    }

}
