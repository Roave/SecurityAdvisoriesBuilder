<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class VersionConstraint
{
    const STABILITY_TAIL           = '[._-]?(?:(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)+)?)?([.-]?dev)?';
    const CLOSED_RANGE_MATCHER     = '/^>(=?)\s*((?:\d+\.)*\d+'.self::STABILITY_TAIL.')\s*,\s*<(=?)\s*((?:\d+\.)*\d+'.self::STABILITY_TAIL.')$/';
    const LEFT_OPEN_RANGE_MATCHER  = '/^<(=?)\s*((?:\d+\.)*\d+'.self::STABILITY_TAIL.')$/';
    const RIGHT_OPEN_RANGE_MATCHER = '/^>(=?)\s*((?:\d+\.)*\d+'.self::STABILITY_TAIL.')$/';

    /**
     * @var string|null
     */
    private $constraintString;

    /**
     * @var Boundary|null
     */
    private $lowerBoundary;

    /**
     * @var Boundary|null
     */
    private $upperBoundary;

    /**
     * @param string $versionConstraint
     *
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromString(string $versionConstraint) : self
    {
        $constraintString = strtolower((string) $versionConstraint);
        $instance         = new self();

        if (preg_match(self::CLOSED_RANGE_MATCHER, $constraintString, $matches)) {
            [$left, $right] = explode(',', $constraintString);

            $instance->lowerBoundary = Boundary::fromString($left);
            $instance->upperBoundary = Boundary::fromString($right);

            return $instance;
        }

        if (preg_match(self::LEFT_OPEN_RANGE_MATCHER, $constraintString, $matches)) {
            $instance->upperBoundary = Boundary::fromString($constraintString);

            return $instance;
        }

        if (preg_match(self::RIGHT_OPEN_RANGE_MATCHER, $constraintString, $matches)) {
            $instance->lowerBoundary = Boundary::fromString($constraintString);

            return $instance;
        }

        $instance->constraintString = $constraintString;

        return $instance;
    }

    public function getConstraintString() : string
    {
        if (null !== $this->constraintString) {
            return $this->constraintString;
        }

        return implode(
            ',',
            array_map(
                function (Boundary $boundary) {
                    return $boundary->getBoundaryString();
                },
                array_filter([$this->lowerBoundary, $this->upperBoundary])
            )
        );
    }

    public function isLowerBoundIncluded() : bool
    {
        return $this->lowerBoundary ? $this->lowerBoundary->limitIncluded() : false;
    }

    public function getLowerBound() : ?Version
    {
        return $this->lowerBoundary ? $this->lowerBoundary->getVersion() : null;
    }

    public function getUpperBound() : ?Version
    {
        return $this->upperBoundary ? $this->upperBoundary->getVersion() : null;
    }

    public function isUpperBoundIncluded() : bool
    {
        return $this->upperBoundary ? $this->upperBoundary->limitIncluded() : false;
    }

    public function canMergeWith(self $other) : bool
    {
        return $this->contains($other)
            || $other->contains($this)
            || $this->overlapsWith($other)
            || $other->overlapsWith($this)
            || $this->adjacentTo($other);
    }

    /**
     * @param VersionConstraint $other
     *
     * @return VersionConstraint
     *
     * @throws \LogicException
     */
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

        throw new \LogicException(sprintf(
            'Cannot merge %s "%s" with %s "%s"',
            self::class,
            $this->getConstraintString(),
            self::class,
            $other->getConstraintString()
        ));
    }

    private function contains(self $other) : bool
    {
        return $this->containsLowerBound($other->lowerBoundary)
            && $this->containsUpperBound($other->upperBoundary);
    }

    private function containsLowerBound(?Boundary $otherLowerBoundary) : bool
    {
        if (! $this->lowerBoundary) {
            return true;
        }

        if (! $otherLowerBoundary) {
            return false;
        }

        if (($this->lowerBoundary->limitIncluded() === $otherLowerBoundary->limitIncluded()) || $this->lowerBoundary->limitIncluded()) {
            return $otherLowerBoundary->getVersion()->isGreaterOrEqualThan($this->lowerBoundary->getVersion());
        }

        return $otherLowerBoundary->getVersion()->isGreaterThan($this->lowerBoundary->getVersion());
    }

    private function containsUpperBound(?Boundary $otherUpperBoundary) : bool
    {
        if (! $this->upperBoundary) {
            return true;
        }

        if (! $otherUpperBoundary) {
            return false;
        }

        if (($this->upperBoundary->limitIncluded() === $otherUpperBoundary->limitIncluded()) || $this->upperBoundary->limitIncluded()) {
            return $this->upperBoundary->getVersion()->isGreaterOrEqualThan($otherUpperBoundary->getVersion());
        }

        return $this->upperBoundary->getVersion()->isGreaterThan($otherUpperBoundary->getVersion());
    }

    private function overlapsWith(VersionConstraint $other) : bool
    {

        if ($this->contains($other) || $other->contains($this)) {
            return false;
        }

        return $this->strictlyContainsOtherBound($other->lowerBoundary)
            xor $this->strictlyContainsOtherBound($other->upperBoundary);
    }

    private function adjacentTo(VersionConstraint $other) : bool
    {
        if ($this->lowerBoundary && $other->upperBoundary && $this->lowerBoundary->adjacentTo($other->upperBoundary)) {
            return true;
        }

        if ($this->upperBoundary && $other->lowerBoundary && $this->upperBoundary->adjacentTo($other->lowerBoundary)) {
            return true;
        }

        return false;
    }

    /**
     * @param VersionConstraint $other
     *
     * @return self
     *
     * @throws \LogicException
     */
    private function mergeWithOverlapping(VersionConstraint $other) : self
    {
        if (! $this->overlapsWith($other)) {
            throw new \LogicException(sprintf(
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
     * @param VersionConstraint $other
     *
     * @return self
     *
     * @throws \LogicException
     */
    private function mergeAdjacent(VersionConstraint $other) : self
    {
        if (! $this->adjacentTo($other)) {
            throw new \LogicException(sprintf(
                '%s "%s" is not adjacent to %s "%s"',
                self::class,
                $this->getConstraintString(),
                self::class,
                $other->getConstraintString()
            ));
        }

        if ($this->upperBoundary && $other->lowerBoundary && $this->upperBoundary->adjacentTo($other->lowerBoundary)) {
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
     * @param Boundary|null $boundary
     *
     * @return bool
     *
     * Note: most of the limitations/complication probably go away if we define a `Bound` VO
     */
    private function strictlyContainsOtherBound(?Boundary $boundary) : bool
    {
        if (! $boundary) {
            return false;
        }

        $boundVersion = $boundary->getVersion();

        if (! $this->lowerBoundary) {
            return $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
        }

        if (! $this->upperBoundary) {
            return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion());
        }

        return $boundVersion->isGreaterThan($this->lowerBoundary->getVersion())
            && $this->upperBoundary->getVersion()->isGreaterThan($boundVersion);
    }
}
