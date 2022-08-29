<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use Psl\Dict;
use Psl\Iter;
use Psl\Regex;
use Psl\Str;
use Psl\Type;
use Psl\Vec;

/** @psalm-immutable */
final class Version
{
    private Flag $flag;

    /** @var list<int> */
    private array $versionNumbers;

    /** @var list<int> */
    private array $stabilityNumbers = [];

    /**
     * @param array{version: string, flag?: string, stability_numbers?: string} $matches
     *
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    private function __construct(array $matches)
    {
        $this->versionNumbers = self::removeTrailingZeroes(Vec\map(
            Str\split($matches['version'], '.'),
            static fn (string $versionComponent): int => (int) $versionComponent,
        ));

        $this->flag = Flag::build($matches['flag'] ?? '');

        $stabilityNumbers = $matches['stability_numbers'] ?? null;
        if ($stabilityNumbers === null) {
            return;
        }

        $this->stabilityNumbers = self::removeTrailingZeroes(Vec\map(
            Str\split($stabilityNumbers, '.'),
            static fn (string $versionComponent): int => (int) $versionComponent,
        ));
    }

    /**
     * @psalm-pure
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    public static function fromString(string $version): self
    {
        $matches = Regex\first_match(
            Str\Byte\lowercase($version),
            '/^' . Matchers::TAGGED_VERSION_MATCHER . '$/',
            Type\shape([
                'version' => Type\string(),
                'stability_numbers' => Type\optional(Type\string()),
                'flag' => Type\optional(Type\string()),
            ]),
        );

        if ($matches === null) {
            throw new InvalidArgumentException(Str\format(
                'Given version "%s" is not a valid version string',
                $version,
            ));
        }

        return new self($matches);
    }

    public function equalTo(self $other): bool
    {
        return $other->versionNumbers === $this->versionNumbers
            && $this->flag->isEqual($other->flag)
            && $this->stabilityNumbers === $other->stabilityNumbers;
    }

    /** @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130} */
    public function isGreaterThan(self $other): bool
    {
        foreach (Vec\keys(Dict\intersect_by_key($this->versionNumbers, $other->versionNumbers)) as $index) {
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
        $result = Iter\count($this->versionNumbers) <=> Iter\count($other->versionNumbers);
        if ($result !== 0) {
            return $result === 1;
        }

        // may be they have stability flags and we can compare them?
        return $this->isStabilityGreaterThan($other);
    }

    /** @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130} */
    private function isStabilityGreaterThan(self $other): bool
    {
        if (! $this->flag->isEqual($other->flag)) {
            return $this->flag->isGreaterThan($other->flag);
        }

        foreach (Vec\keys(Dict\intersect_by_key($this->stabilityNumbers, $other->stabilityNumbers)) as $index) {
            if ($this->stabilityNumbers[$index] > $other->stabilityNumbers[$index]) {
                return true;
            }

            if ($this->stabilityNumbers[$index] < $other->stabilityNumbers[$index]) {
                return false;
            }
        }

        return Iter\count($this->stabilityNumbers) > Iter\count($other->stabilityNumbers);
    }

    /**
     * Compares two versions and sees if this one is greater or equal than the given one
     *
     * @todo may become a simple array comparison (if PHP supports it)
     */
    public function isGreaterOrEqualThan(self $other): bool
    {
        return $this->equalTo($other) || $this->isGreaterThan($other);
    }

    /** @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130} */
    public function getVersion(): string
    {
        $version = Str\join(Vec\map(
            $this->versionNumbers,
            static fn (int $number): string => (string) $number,
        ), '.');

        $flagLiteral = $this->flag->getLiteral();
        if ($flagLiteral !== '') {
            $version .= '-' . $flagLiteral;

            if ($this->stabilityNumbers !== []) {
                $version .= '.' . Str\join(Vec\map(
                    $this->stabilityNumbers,
                    static fn (int $number): string => (string) $number,
                ), '.');
            }
        }

        return $version;
    }

    /**
     * @psalm-param list<int> $versionNumbers
     *
     * @return int[]
     * @psalm-return list<int>
     */
    private static function removeTrailingZeroes(array $versionNumbers): array
    {
        foreach (Vec\reverse(Vec\keys($versionNumbers)) as $key) {
            if ($versionNumbers[$key] !== 0) {
                return Vec\values(Dict\slice(
                    $versionNumbers,
                    0,
                    Type\positive_int()->assert($key + 1),
                ));
            }
        }

        return [0];
    }
}
