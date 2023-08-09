<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MatchNoneConstraint;
use Composer\Semver\Constraint\MultiConstraint;
use Composer\Semver\Intervals;
use Composer\Semver\VersionParser;
use InvalidArgumentException;
use LogicException;
use Psl;
use Psl\Regex;
use Psl\Str;
use Psl\Vec;
use Roave\SecurityAdvisories\Exception\InvalidVersionConstraint;

use function explode;

/**
 * A simple version constraint - naively assumes that it is only about ranges like ">=1.2.3,<4.5.6"
 *
 * @psalm-immutable
 */
final class VersionConstraint
{
    private string|null $constraintString = null;

    private Boundary|null $lowerBoundary = null;

    private Boundary|null $upperBoundary = null;

    private function __construct(private readonly ConstraintInterface $constraint)
    {
    }

    /**
     * @throws InvalidArgumentException
     *
     * @psalm-pure
     */
    public static function fromString(string $versionConstraint): self
    {
        $parser = new VersionParser();
        
        $constraintString = $versionConstraint;
        $instance         = new self(Intervals::compactConstraint($parser->parseConstraints($versionConstraint)));

        if (Regex\matches($constraintString, Matchers::CLOSED_RANGE_MATCHER)) {
            [$left, $right] = explode(',', $constraintString);

            $instance->lowerBoundary = Boundary::fromString($left);
            $instance->upperBoundary = Boundary::fromString($right);

            return $instance;
        }

        if (Regex\matches($constraintString, Matchers::LEFT_OPEN_RANGE_MATCHER)) {
            $instance->upperBoundary = Boundary::fromString($constraintString);

            return $instance;
        }

        if (Regex\matches($constraintString, Matchers::RIGHT_OPEN_RANGE_MATCHER)) {
            $instance->lowerBoundary = Boundary::fromString($constraintString);

            return $instance;
        }
        
//        $parser = new VersionParser();
//        
//        $r = $parser->parseConstraints($constraintString);
//        
//        error_log(var_export($r, true));
//
//        throw InvalidVersionConstraint::from($constraintString);
        // @TODO log here??

        $instance->constraintString = $constraintString;

        return $instance;
    }

    public function isSimpleRangeString(): bool
    {
        return $this->constraintString === null;
    }

    public function getConstraintString(): string
    {
        return self::constraintToString($this->constraint);
        /** @psalm-suppress ImpureFunctionCall - conditional purity */
        return $this->constraintString ?? Str\join(
            Vec\map(
                Vec\filter_nulls([$this->lowerBoundary, $this->upperBoundary]),
                static function (Boundary $boundary) {
                    return $boundary->getBoundaryString();
                },
            ),
            ',',
        );
    }
    
    private static function constraintToString(ConstraintInterface $constraint): string
    {
        if ($constraint instanceof MultiConstraint) {
            return implode(
                $constraint->isConjunctive()
                    ? ','
                    : '|',
                array_map([self::class, 'constraintToString'], $constraint->getConstraints())
            );
        }

        if ($constraint instanceof Constraint) {
            return Psl\Regex\replace( 
                Psl\Regex\replace($constraint->__toString(), '/((\.0)+(-dev)?)+$/', ''),
                '/(\s)+/',
                ''
            );
        }

        if ($constraint instanceof MatchNoneConstraint) {
            return '<999,>999'; // impossible constraint - same as a "match nothing"
        }

        return $constraint->__toString();
    }

    public function isLowerBoundIncluded(): bool
    {
        return $this->lowerBoundary !== null && $this->lowerBoundary->limitIncluded();
    }

    public function getLowerBound(): Version|null
    {
        return $this->lowerBoundary?->getVersion();
    }

    public function getUpperBound(): Version|null
    {
        return $this->upperBoundary?->getVersion();
    }

    public function isUpperBoundIncluded(): bool
    {
        return $this->upperBoundary !== null && $this->upperBoundary->limitIncluded();
    }

    public function canMergeWith(self $other): bool
    {
        return $this->contains($other)
            || $other->contains($this)
            || $this->overlapsWith($other)
            || $other->overlapsWith($this)
            || $this->adjacentTo($other);
    }

    /** @throws LogicException */
    public function mergeWith(self $other): self
    {
        if ($this->contains($other)) {
            return $this;
        }

        if ($other->contains($this)) {
            return $other;
        }

        if ($this->overlapsWith($other)) {
            return $this->mergeWithOverlapping($other);
        }

        if ($other->overlapsWith($this)) {
            return $other->mergeWithOverlapping($this);
        }

        if ($this->adjacentTo($other)) {
            return $this->mergeAdjacent($other);
        }

        throw new LogicException(Str\format(
            'Cannot merge %s "%s" with %s "%s"',
            self::class,
            $this->getConstraintString(),
            self::class,
            $other->getConstraintString(),
        ));
    }

    private function contains(self $other): bool
    {
        return $this->isSimpleRangeString()  // cannot compare - too complex :-(
            && $other->isSimpleRangeString() // cannot compare - too complex :-(
            && $this->containsLowerBound($other->lowerBoundary)
            && $this->containsUpperBound($other->upperBoundary);
    }

    private function containsLowerBound(Boundary|null $otherLowerBoundary): bool
    {
        if ($this->lowerBoundary === null) {
            return true;
        }

        if ($otherLowerBoundary === null) {
            return false;
        }

        $isLowerLimitIncluded = $this->lowerBoundary->limitIncluded();
        if ($isLowerLimitIncluded || ! $otherLowerBoundary->limitIncluded()) {
            return $otherLowerBoundary->getVersion()->isGreaterOrEqualThan($this->lowerBoundary->getVersion());
        }

        return $otherLowerBoundary->getVersion()->isGreaterThan($this->lowerBoundary->getVersion());
    }

    private function containsUpperBound(Boundary|null $otherUpperBoundary): bool
    {
        if ($this->upperBoundary === null) {
            return true;
        }

        if ($otherUpperBoundary === null) {
            return false;
        }

        $upperLimitIncluded = $this->upperBoundary->limitIncluded();
        if ($upperLimitIncluded || ! $otherUpperBoundary->limitIncluded()) {
            return $this->upperBoundary->getVersion()->isGreaterOrEqualThan($otherUpperBoundary->getVersion());
        }

        return $this->upperBoundary->getVersion()->isGreaterThan($otherUpperBoundary->getVersion());
    }

    private function overlapsWith(VersionConstraint $other): bool
    {
        if (! $this->isSimpleRangeString() && $other->isSimpleRangeString()) {
            return false;
        }

        return $this->strictlyContainsOtherBound($other->lowerBoundary)
            xor $this->strictlyContainsOtherBound($other->upperBoundary);
    }

    private function adjacentTo(VersionConstraint $other): bool
    {
        if (
            $this->lowerBoundary !== null
            && $other->upperBoundary !== null
            && $this->lowerBoundary->adjacentTo($other->upperBoundary)
        ) {
            return true;
        }

        return $this->upperBoundary !== null
            && $other->lowerBoundary !== null
            && $this->upperBoundary->adjacentTo($other->lowerBoundary);
    }

    /** @throws LogicException */
    private function mergeWithOverlapping(VersionConstraint $other): self
    {
        if (! $this->overlapsWith($other)) {
            throw new LogicException(Str\format(
                '%s "%s" does not overlap with %s "%s"',
                self::class,
                $this->getConstraintString(),
                self::class,
                $other->getConstraintString(),
            ));
        }

        $instance = new self(Intervals::compactConstraint(
            self::fromString(
                self::constraintToString($this->constraint) . '|' . self::constraintToString($other->constraint)
            )->constraint
        ));

        if ($this->strictlyContainsOtherBound($other->lowerBoundary)) {
            $instance->lowerBoundary = $this->lowerBoundary;
            $instance->upperBoundary = $other->upperBoundary;

            return $instance;
        }

        $instance->lowerBoundary = $other->lowerBoundary;
        $instance->upperBoundary = $this->upperBoundary;

        return $instance;
    }

    private function mergeAdjacent(VersionConstraint $other): self
    {
        $instance = new self(Intervals::compactConstraint(
            self::fromString(
                self::constraintToString($this->constraint) . '|' . self::constraintToString($other->constraint)
            )->constraint
        ));

        if (
            $this->upperBoundary !== null
            && $other->lowerBoundary !== null
            && $this->upperBoundary->adjacentTo($other->lowerBoundary)
        ) {
            $instance->lowerBoundary = $this->lowerBoundary;
            $instance->upperBoundary = $other->upperBoundary;

            return $instance;
        }

        $instance->lowerBoundary = $other->lowerBoundary;
        $instance->upperBoundary = $this->upperBoundary;

        return $instance;
    }

    /** Note: most of the limitations/complication probably go away if we define a `Bound` VO */
    private function strictlyContainsOtherBound(Boundary|null $boundary): bool
    {
        if ($boundary === null) {
            return false;
        }

        $boundVersion = $boundary->getVersion();

        if ($this->lowerBoundary === null) {
            Psl\invariant($this->upperBoundary !== null, 'We either have a lower or an upper boundary, or both');

            return $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
        }

        if ($this->upperBoundary === null) {
            return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion());
        }

        return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion())
            && $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
    }
}
