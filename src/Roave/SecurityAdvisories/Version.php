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
    private const VERSION_MATCHER = <<<REGEXP
        /^((?:\d+\.)*\d+)[._-]?(?:(stable|beta|b|rc|alpha|a|patch|p)[._-]?((?:\d+\.)*\d+)?)?/
        REGEXP;

    /** @var int[] */
    private $versionNumbers;

    /** @var VersionStability */
    private $versionStability;

    private function __construct(array $versionNumbers, array $versionStability)
    {
        $this->versionNumbers = $versionNumbers;
        $this->versionStability = new VersionStability($versionStability ?? []);
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromString(string $version) : self
    {
        if (preg_match(self::VERSION_MATCHER, strtolower($version), $matches) !== 1) {
            throw new InvalidArgumentException(sprintf('Given version "%s" is not a valid version string', $version));
        }

        $version = self::removeTrailingZeroes(...array_map('intval', explode('.', $matches[1])));

        return new self($version, array_slice($matches, 2));
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

        // we can continue only when versions are equal
        $isGreater = count($this->versionNumbers) <=> count($other->versionNumbers);

        if ($isGreater != 0) {
            return $isGreater == 1 ? true : false;
        }

        // compare here stabilities - flags and versions
        $isGreater = $this->versionStability->isGreaterThan($other->versionStability);

        if ($isGreater != 0) {
            return $isGreater == 1 ? true : false;
        }

        // the only chance we get here is when versions are absolutely equal to each other
        return false;
    }

    private function isEqualTo(self $other) : bool
    {
        return $other->versionNumbers === $this->versionNumbers &&
            $this->versionStability->isEqualTo($other->versionStability);
    }

    /**
     * Compares two versions and sees if this one is greater or equal than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterOrEqualThan(self $other) : bool
    {
        return $this->isEqualTo($other)
            || $this->isGreaterThan($other);
    }

    public function getVersion() : string
    {
        $stability = $this->versionStability instanceof VersionStability ? $this->versionStability->getVersion() : '';

        return implode('.', $this->versionNumbers) . (!empty($stability) ? '-'.$stability:'');
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
