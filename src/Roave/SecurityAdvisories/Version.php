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
        if (preg_match('/^' . Matchers::TAGGED_VERSION_MATCHER . '$/', strtolower($version), $matches) !== 1) {
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
     * Mode of operation is the following:
     *      - compare version numbers (if equal try to compare stabilities)
     *      - compare flags
     *      - compare stability versions
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
        } // note: I do not see where I use -1 probably we can get rid of it

        /*
         * Check case when we have 1.2.3 vs. 1.2.3.4.
         * Here the latter is greater than the former so it will return false.
         * Continue only when versions are equal, as in <=> returns 0
         */
        $isGreater = count($this->versionNumbers) <=> count($other->versionNumbers);
        if ($isGreater != 0) {
            return $isGreater == 1 ? true : false;
        }

        // may be they have stability flags and we can compare them?
        $isGreater = $this->isStabilityGreaterThan($other);

        return $isGreater == 1;
    }

    private function isStabilityGreaterThan(self $other) : int
    {
        // does not make sense to continue without flag,
        // if no flags exist then it will be parsed like a long version
        if ($this->flag == null && $other->flag == null) {
            return 0;
        }

        $isGreater = $this->compareFlags($other);

        if ($isGreater !== 0) {
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

    /**
     *
     * Bear in mind that we compare flags only when versions are equal
     *
     * @param Version $other
     *
     * @return int
     */
    private function compareFlags(self $other) : int
    {
        $patchLiterals = [
            'p',
            'patch',
        ];

        // patch is greater than any other version
        if (
            in_array($this->flag, $patchLiterals) &&
            !in_array($other->flag, $patchLiterals)
        ) {
            return 1;
        }

        if (
            !in_array($this->flag, $patchLiterals) &&
            in_array($other->flag, $patchLiterals)
        ) {
            return -1;
        }

        if (
            in_array($this->flag, $patchLiterals) &&
            in_array($other->flag, $patchLiterals)
        ) {
            return 0;
        }

        if ($this->flag == null && $other->flag != null) {
            return 1;
        }

        if ($this->flag != null && $other->flag == null) {
            return -1;
        }

        return self::FLAGS_HIERARCHY[$this->flag] <=> self::FLAGS_HIERARCHY[$other->flag];
    }
}
