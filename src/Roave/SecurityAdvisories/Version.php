<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class Version
{
    const STABILITY_TAIL = '[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?([.-]?dev)?';
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
        return (bool) version_compare($first, $second, '==');
    }

    public function isGreaterThan(self $other) : bool
    {
        [$first, $second] = $this->normalizeVersions($other);
        return (bool) version_compare($first, $second, '>');
    }

    public function isGreaterOrEqualThan(self $other) : bool
    {
        [$first, $second] = $this->normalizeVersions($other);
        return (bool) version_compare($first, $second, '>=');
    }

    public function toString()
    {
        return $this->version;
    }

    /**
     * Here we need to append zeroes so comparison will work correctly
     *
     * @param Version $other
     *
     * @return array
     */
    private function normalizeVersions(Version $other): array
    {

        // strip the stability tail and save it for later
        // compare by count of version in strgin

        [$versionA, $tailA] = $this->stabilizeVersion($this->version);
        [$versionB, $tailB] = $this->stabilizeVersion($other->version);

        $comp = substr_count($versionA, '.') <=> substr_count($versionB, '.');
        switch ($comp) {
            case -1:
                $count = substr_count($versionB, '.') - substr_count($versionA, '.');
                return [$versionA.str_repeat('.0', $count).$tailA, $versionB.$tailB];
            case 0;
                return [$versionA.$tailA, $versionB.$tailB];
            case 1;
                $count = substr_count($versionA, '.') - substr_count($versionB, '.');
                return [$versionA.$tailA, $versionB.str_repeat('.0', $count).$tailB];
        }

        // detect which version does not have equal length, take into account stability tails
        // do the padding for the that version


    }

    private function stabilizeVersion(string $version) : array
    {
        // todo: do beautify
        preg_match('/[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?([.-]?dev)?$/',
            $version, $matches, PREG_OFFSET_CAPTURE);

        if (!is_null($matches[0][0])) {
            return [substr($version, 0, $matches[0][1]), $matches[0][0]];
        }
        return [$version, null];


    }

}
