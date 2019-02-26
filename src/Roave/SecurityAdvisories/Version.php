<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use function array_filter;
use function array_key_exists;
use function array_map;
use function array_slice;
use function count;
use function explode;
use function implode;
use function Safe\preg_match;
use function Safe\sprintf;

/**
 * A simple version, such as 1.0 or 1.0.0.0 or 2.0.1.3.2
 */
final class Version
{
    public const VALIDITY_MATCHER = '/^(?:\d+\.)*\d+$/';

    /** @var int[] */
    private $versionNumbers;

    private function __construct(int ...$versionNumbers)
    {
        $this->versionNumbers = $versionNumbers;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromString(string $version) : self
    {
        if (preg_match(self::VALIDITY_MATCHER, $version) !== 1) {
            throw new InvalidArgumentException(sprintf('Given version "%s" is not a valid version string', $version));
        }

        return new self(...self::removeTrailingZeroes(...array_map('intval', explode('.', $version))));
    }

    public function equalTo(self $other) : bool
    {
        return $other->versionNumbers === $this->versionNumbers;
    }

    /**
     * Compares two versions and sees if this one is greater than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterThan(self $other) : bool
    {
        foreach ($other->versionNumbers as $index => $otherVersion) {
            if (! array_key_exists($index, $this->versionNumbers)) {
                return false;
            }

            if ($this->versionNumbers[$index] === $otherVersion) {
                continue;
            }

            return $this->versionNumbers[$index] > $otherVersion;
        }

        return (bool) array_filter(array_slice($this->versionNumbers, count($other->versionNumbers)));
    }

    /**
     * Compares two versions and sees if this one is greater or equal than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterOrEqualThan(self $other) : bool
    {
        foreach ($other->versionNumbers as $index => $otherVersion) {
            $thisVersion = $this->versionNumbers[$index] ?? 0;

            if ($thisVersion === $otherVersion) {
                continue;
            }

            return $thisVersion > $otherVersion;
        }

        return true;
    }

    public function getVersion() : string
    {
        return implode('.', $this->versionNumbers);
    }

    /** @return int[] */
    private static function removeTrailingZeroes(int ...$versionNumbers) : array
    {
        $i = count($versionNumbers) - 1;

        while ($i > 0) {
            if ($versionNumbers[$i] > 0) {
                break;
            }

            $i -= 1;
        }

        return array_slice($versionNumbers, 0, $i + 1);
    }
}
