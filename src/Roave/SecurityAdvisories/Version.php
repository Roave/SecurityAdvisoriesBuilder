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
use function preg_match;
use function Safe\sprintf;
use function strtolower;

final class Version
{
    private Flag $flag;

    /**
     * @var int[]
     * @psalm-param list<int>
     */
    private array $versionNumbers;

    /**
     * @var int[]
     * @psalm-param list<int>
     */
    private array $stabilityNumbers;

    /**
     * @param string[] $matches
     */
    private function __construct(array $matches)
    {
        $this->versionNumbers = self::removeTrailingZeroes(...array_map('intval', explode('.', $matches['version'])));

        $this->flag = Flag::build($matches['flag'] ?? '');

        $this->stabilityNumbers = [];
        if (! isset($matches['stability_numbers'])) {
            return;
        }

        $this->stabilityNumbers = self::removeTrailingZeroes(
            ...array_map('intval', explode('.', $matches['stability_numbers']))
        );
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

        return new self($matches);
    }

    public function equalTo(self $other) : bool
    {
        return $other->versionNumbers === $this->versionNumbers
            && $this->flag->isEqual($other->flag)
            && $this->stabilityNumbers === $other->stabilityNumbers;
    }

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

        /*
         * Check case when we have 1.2.3 vs. 1.2.3.4.
         * Here the latter is greater than the former so <=> will return -1.
         * Continue only when versions are equal, as in <=> returns 0
         */
        $result = count($this->versionNumbers) <=> count($other->versionNumbers);
        if ($result !== 0) {
            return $result === 1;
        }

        // may be they have stability flags and we can compare them?
        return $this->isStabilityGreaterThan($other);
    }

    private function isStabilityGreaterThan(self $other) : bool
    {
        if (! $this->flag->isEqual($other->flag)) {
            return $this->flag->isGreaterThan($other->flag);
        }

        foreach (array_keys(array_intersect_key($this->stabilityNumbers, $other->stabilityNumbers)) as $index) {
            if ($this->stabilityNumbers[$index] > $other->stabilityNumbers[$index]) {
                return true;
            }

            if ($this->stabilityNumbers[$index] < $other->stabilityNumbers[$index]) {
                return false;
            }
        }

        return count($this->stabilityNumbers) > count($other->stabilityNumbers);
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

        $flagLiteral = $this->flag->getLiteral();
        if ($flagLiteral !== '') {
            $version .= '-' . $flagLiteral;

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
}
