<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use LogicException;
use function array_filter;
use function array_map;
use function assert;
use function explode;
use function implode;
use function Safe\preg_match;
use function Safe\sprintf;

/**
 * A simple version constraint - naively assumes that it is only about ranges like ">=1.2.3,<4.5.6"
 */
final class VersionConstraint
{
    public const CLOSED_RANGE_MATCHER     = '/^>(=?)\s*((?:\d+\.)*\d+)\s*,\s*<(=?)\s*((?:\d+\.)*\d+)$/';
    public const LEFT_OPEN_RANGE_MATCHER  = '/^<(=?)\s*((?:\d+\.)*\d+)$/';
    public const RIGHT_OPEN_RANGE_MATCHER = '/^>(=?)\s*((?:\d+\.)*\d+)$/';

    /** @var string|null */
    private $constraintString;

    /** @var Boundary|null */
    private $lowerBoundary;

    /** @var Boundary|null */
    private $upperBoundary;

    private function __construct()
    {
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromString(string $versionConstraint) : self
    {
        $constraintString = $versionConstraint;
        $instance         = new self();

        if (preg_match(self::CLOSED_RANGE_MATCHER, $constraintString, $matches) === 1) {
            [$left, $right] = explode(',', $constraintString);

            $instance->lowerBoundary = Boundary::fromString($left);
            $instance->upperBoundary = Boundary::fromString($right);

            return $instance;
        }

        if (preg_match(self::LEFT_OPEN_RANGE_MATCHER, $constraintString, $matches) === 1) {
            $instance->upperBoundary = Boundary::fromString($constraintString);

            return $instance;
        }

        if (preg_match(self::RIGHT_OPEN_RANGE_MATCHER, $constraintString, $matches) === 1) {
            $instance->lowerBoundary = Boundary::fromString($constraintString);

            return $instance;
        }

        $instance->constraintString = $constraintString;

        return $instance;
    }

    public function isSimpleRangeString() : bool
    {
        return $this->constraintString === null;
    }

    public function getConstraintString() : string
    {
        if ($this->constraintString !== null) {
            return $this->constraintString;
        }

        return implode(
            ',',
            array_map(
                static function (Boundary $boundary) {
                    return $boundary->getBoundaryString();
                },
                array_filter([$this->lowerBoundary, $this->upperBoundary])
            )
        );
    }

    public function isLowerBoundIncluded() : bool
    {
        return $this->lowerBoundary !== null ? $this->lowerBoundary->limitIncluded() : false;
    }

    public function getLowerBound() : ?Version
    {
        return $this->lowerBoundary !== null ? $this->lowerBoundary->getVersion() : null;
    }

    public function getUpperBound() : ?Version
    {
        return $this->upperBoundary !== null ? $this->upperBoundary->getVersion() : null;
    }

    public function isUpperBoundIncluded() : bool
    {
        return $this->upperBoundary !== null ? $this->upperBoundary->limitIncluded() : false;
    }

    public function canMergeWith(self $other) : bool
    {
        return $this->contains($other)
            || $other->contains($this)
            || $this->overlapsWith($other)
            || $other->overlapsWith($this)
            || $this->adjacentTo($other);
    }

    /** @throws LogicException */
    public function mergeWith(self $other) : self
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

        throw new LogicException(sprintf(
            'Cannot merge %s "%s" with %s "%s"',
            self::class,
            $this->getConstraintString(),
            self::class,
            $other->getConstraintString()
        ));
    }

    private function contains(self $other) : bool
    {
        return $this->isSimpleRangeString()  // cannot compare - too complex :-(
            && $other->isSimpleRangeString() // cannot compare - too complex :-(
            && $this->containsLowerBound($other->lowerBoundary)
            && $this->containsUpperBound($other->upperBoundary);
    }

    private function containsLowerBound(?Boundary $otherLowerBoundary) : bool
    {
        if ($this->lowerBoundary === null) {
            return true;
        }

        if ($otherLowerBoundary === null) {
            return false;
        }

        if (($this->lowerBoundary->limitIncluded() === $otherLowerBoundary->limitIncluded())
            || $this->lowerBoundary->limitIncluded()
        ) {
            return $otherLowerBoundary->getVersion()->isGreaterOrEqualThan($this->lowerBoundary->getVersion());
        }

        return $otherLowerBoundary->getVersion()->isGreaterThan($this->lowerBoundary->getVersion());
    }

    private function containsUpperBound(?Boundary $otherUpperBoundary) : bool
    {
        if ($this->upperBoundary === null) {
            return true;
        }

        if ($otherUpperBoundary === null) {
            return false;
        }

        $upperLimitIncluded = $this->upperBoundary->limitIncluded();

        if ($upperLimitIncluded || ($upperLimitIncluded === $otherUpperBoundary->limitIncluded())) {
            return $this->upperBoundary->getVersion()->isGreaterOrEqualThan($otherUpperBoundary->getVersion());
        }

        return $this->upperBoundary->getVersion()->isGreaterThan($otherUpperBoundary->getVersion());
    }

    private function overlapsWith(VersionConstraint $other) : bool
    {
        if (! $this->isSimpleRangeString() && $other->isSimpleRangeString()) {
            return false;
        }

        return $this->strictlyContainsOtherBound($other->lowerBoundary)
            xor $this->strictlyContainsOtherBound($other->upperBoundary);
    }

    private function adjacentTo(VersionConstraint $other) : bool
    {
        if ($this->lowerBoundary !== null
            && $other->upperBoundary !== null
            && $this->lowerBoundary->adjacentTo($other->upperBoundary)
        ) {
            return true;
        }

        if ($this->upperBoundary !== null
            && $other->lowerBoundary !== null
            && $this->upperBoundary->adjacentTo($other->lowerBoundary)
        ) {
            return true;
        }

        return false;
    }

    /**
     * @throws LogicException
     */
    private function mergeWithOverlapping(VersionConstraint $other) : self
    {
        if (! $this->overlapsWith($other)) {
            throw new LogicException(sprintf(
                '%s "%s" does not overlap with %s "%s"',
                self::class,
                $this->getConstraintString(),
                self::class,
                $other->getConstraintString()
            ));
        }

        if ($this->strictlyContainsOtherBound($other->lowerBoundary)) {
            $instance = new self();

            $instance->lowerBoundary = $this->lowerBoundary;
            $instance->upperBoundary = $other->upperBoundary;

            return $instance;
        }

        $instance = new self();

        $instance->lowerBoundary = $other->lowerBoundary;
        $instance->upperBoundary = $this->upperBoundary;

        return $instance;
    }


    /**
     * @throws LogicException
     */
    private function mergeAdjacent(VersionConstraint $other) : self
    {
        if (! $this->adjacentTo($other)) {
            throw new LogicException(sprintf(
                '%s "%s" is not adjacent to %s "%s"',
                self::class,
                $this->getConstraintString(),
                self::class,
                $other->getConstraintString()
            ));
        }

        if ($this->upperBoundary !== null
            && $other->lowerBoundary !== null
            && $this->upperBoundary->adjacentTo($other->lowerBoundary)
        ) {
            $instance = new self();

            $instance->lowerBoundary = $this->lowerBoundary;
            $instance->upperBoundary = $other->upperBoundary;

            return $instance;
        }

        $instance = new self();

        $instance->lowerBoundary = $other->lowerBoundary;
        $instance->upperBoundary = $this->upperBoundary;

        return $instance;
    }

    /** Note: most of the limitations/complication probably go away if we define a `Bound` VO */
    private function strictlyContainsOtherBound(?Boundary $boundary) : bool
    {
        if ($boundary === null) {
            return false;
        }

        $boundVersion = $boundary->getVersion();

        if ($this->lowerBoundary === null) {
            assert($this->upperBoundary !== null, 'We either have a lower or an upper boundary, or both');

            return $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
        }

        if ($this->upperBoundary === null) {
            return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion());
        }

        return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion())
            && $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
    }
}
