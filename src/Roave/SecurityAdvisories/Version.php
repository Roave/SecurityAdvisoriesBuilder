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
     * @return array
     */
    private function normalizeVersions(self $other): array
    {
        $first = $this->version;
        $second = $this->version;

        // detect which version does not have equal length, take into account stability tails
        // do the padding for the that version

        return [$first, $second];
    }

}
