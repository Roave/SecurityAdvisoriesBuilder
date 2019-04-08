<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use Safe\Exceptions\PcreException;
use Safe\Exceptions\StringsException;
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
use function strtolower;

final class Version
{
    /** @var int[] */
    private $versionNumbers;

    /** @var string|null  */
    private $flag;

    /** @var int[]  */
    private $stabilityNumbers;

    private const FLAGS_HIERARCHY = [
        'stable'    => 4,
        'rc'        => 3,
        'beta'      => 2,
        'b'         => 2,
        'alpha'     => 1,
        'a'         => 1,
        'patch'     => 0,
        'p'         => 0,
    ];

    private function __construct()
    {
    }

    /**
     * @return Version
     *
     * @throws PcreException
     * @throws StringsException
     */
    public static function fromString(string $version) : self
    {
        if (preg_match('/' . RegExp::TAGGED_VERSION_MATCHER . '/', strtolower($version), $matches) !== 1) {
            throw new InvalidArgumentException(sprintf('Given version "%s" is not a valid version string', $version));
        }

        $object = new self();

        $object->versionNumbers = self::removeTrailingZeroes(...array_map('intval', explode('.', $matches['version'])));

        $object->flag = $matches['flag'] ?? null;

        if ($matches['stability_numbers'] ?? null) {
            $numbers = self::removeTrailingZeroes(...array_map('intval', explode('.', $matches['stability_numbers'])));
        }

        $object->stabilityNumbers = $numbers ?? [];

        return $object;
    }

    public function equalTo(self $other) : bool
    {
        return $other->versionNumbers === $this->versionNumbers &&
            $this->stabilityEqualTo($other);
    }

    private function stabilityEqualTo(self $other) : bool
    {
        // if we have no flags at all then stability parts are equal
        if ($this->flag === null && $other->flag === null) {
            return true;
        }

        if ($this->flag === null || $other->flag === null) {
            return false;
        }

        return self::FLAGS_HIERARCHY[$this->flag] === self::FLAGS_HIERARCHY[$other->flag] &&
            $this->stabilityNumbers === $other->stabilityNumbers;
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

        if ($isGreater) {
            return $isGreater === 1 ? true : false;
        }

        // compare here stabilities - flags and versions
        $isGreater = $this->isStabilityGreaterThan($other);

        if ($isGreater) {
            return $isGreater === 1 ? true : false;
        }

        // the only chance we get here is when versions are absolutely equal to each other
        return false;
    }

    private function isStabilityGreaterThan(self $other) : int
    {
        if ($this->flag === null && $other->flag === null) {
            return 0;
        }

        if ($this->flag === null && $other->flag !== null) {
            return 1;
        }

        if ($this->flag !== null && $other->flag === null) {
            return -1;
        }

        $isGreater = $this->compareFlags($other);

        if ($isGreater) {
            return $isGreater;
        }

        // compare versions here
        foreach (array_keys(array_intersect_key($this->stabilityNumbers, $other->stabilityNumbers)) as $index) {
            if ($this->stabilityNumbers[$index] > $other->stabilityNumbers[$index]) {
                return 1;
            }

            if ($this->stabilityNumbers[$index] < $other->stabilityNumbers[$index]) {
                return -1;
            }
        }

        return count($this->stabilityNumbers) <=> count($other->stabilityNumbers);
    }

    /**
     * Compares two versions and sees if this one is greater or equal than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterOrEqualThan(self $other) : bool
    {
        return $this->equalTo($other)
            || $this->isGreaterThan($other);
    }

    public function getVersion() : string
    {
        $version = implode('.', $this->versionNumbers);

        if ($this->flag !== null) {
            $version .= '-' . $this->flag;

            if ($this->stabilityNumbers !== []) {
                $version .= '.' . implode('.', $this->stabilityNumbers);
            }
        }

        return $version;
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

    private function compareFlags(self $other) : int
    {
        return self::FLAGS_HIERARCHY[$this->flag] <=> self::FLAGS_HIERARCHY[$other->flag];
    }
}
