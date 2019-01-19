<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class Version
{
    const STABILITY_TAIL = '[._-]?'.
                           '(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?'.
                           '([.-]?dev)?';

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
        [$first, $second] = $this->normalizeVersions($other);
        return version_compare($first, $second, '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        [$first, $second] = $this->normalizeVersions($other);
        return version_compare($first, $second, '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        [$first, $second] = $this->normalizeVersions($other);
        return version_compare($first, $second, '>=');
    }

    public function toString()
    {
        return $this->version;
    }

    /**
     * Here we need to append zeroes so comparison will work correctly
     */
    private function normalizeVersions(Version $other): array
    {
        [$versionA, $tailA] = $this->stabilizeVersion($this->version);
        [$versionB, $tailB] = $this->stabilizeVersion($other->version);

        [$countA, $countB, $diff] = $this->getVersionStats($versionA, $versionB);
        switch ($countA <=> $countB) {
            case -1:
                return [
                    $versionA.str_repeat('.0', $diff).$tailA,
                    $versionB.$tailB
                ];
            case 0;
                return [
                    $versionA.$tailA,
                    $versionB.$tailB
                ];
            case 1;
                return [
                    $versionA.$tailA,
                    $versionB.str_repeat('.0', $diff).$tailB
                ];
        }
    }

    /**
     * Split version string representation in two parts - stable and stability tail,
     * if no tail is present return null
     */
    private function stabilizeVersion(string $version) : array
    {
        $regExp = '/'.self::STABILITY_TAIL.'$/';
        preg_match($regExp, $version, $matches, PREG_OFFSET_CAPTURE);

        if (!is_null($matches[0][0])) {
            return [substr($version, 0, $matches[0][1]), $matches[0][0]];
        }

        return [$version, null];
    }

    /**
     * Get count of version numbers for each version
     * also return difference in version numbers between versions
     */
    private function getVersionStats(string $versionA, string $versionB) : array
    {
        $first = substr_count($versionA, '.');
        $second = substr_count($versionB, '.');

        return [
            $first,
            $second,
            abs($first - $second),
        ];
    }

}
