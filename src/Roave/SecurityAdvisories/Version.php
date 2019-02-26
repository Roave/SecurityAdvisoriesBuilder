<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use function array_intersect_key;
use function array_keys;
use function array_map;
use function array_reverse;
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
    private const VALIDITY_MATCHER = '/^(?:\d+\.)*\d+$/';

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
        foreach (array_keys(array_intersect_key($this->versionNumbers, $other->versionNumbers)) as $index) {
            if ($this->versionNumbers[$index] > $other->versionNumbers[$index]) {
                return true;
            }

            if ($this->versionNumbers[$index] < $other->versionNumbers[$index]) {
                return false;
            }
        }

        return count($this->versionNumbers) > count($other->versionNumbers);
    }

    /**
     * Compares two versions and sees if this one is greater or equal than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterOrEqualThan(self $other) : bool
    {
        return $other->versionNumbers === $this->versionNumbers
            || $this->isGreaterThan($other);
    }

    public function getVersion() : string
    {
        return implode('.', $this->versionNumbers);
    }

    /** @return int[] */
    private static function removeTrailingZeroes(int ...$versionNumbers) : array
    {
        foreach (array_reverse(array_keys($versionNumbers)) as $key) {
            if ($versionNumbers[$key] !== 0) {
                return array_slice($versionNumbers, 0, $key + 1);
            }
        }

        return [0];
    }
}
