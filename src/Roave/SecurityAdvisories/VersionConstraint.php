<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Composer\Semver\Constraint\Constraint;
use Composer\Semver\Constraint\ConstraintInterface;
use Composer\Semver\Constraint\MatchNoneConstraint;
use Composer\Semver\Constraint\MultiConstraint;
use Composer\Semver\Intervals;
use Composer\Semver\Semver;
use Composer\Semver\VersionParser;
use InvalidArgumentException;
use LogicException;
use Psl;

use function explode;

/**
 * A simple version constraint - naively assumes that it is only about ranges like ">=1.2.3,<4.5.6"
 *
 * @psalm-immutable
 */
final class VersionConstraint
{
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
        /** @psalm-suppress ImpureMethodCall besides memoization, {@see Intervals} is pure */
        return new self(Intervals::compactConstraint((new VersionParser())->parseConstraints($versionConstraint)));
    }

    public function getConstraintString(): string
    {
        return self::constraintToString($this->constraint);
    }

    /** @pure */
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
            /** @psalm-suppress ImpureMethodCall besides memoization, {@see ConstraintInterface::__toString} is pure */
            return Psl\Regex\replace( 
                Psl\Regex\replace( 
                    $constraint->__toString(),
                    '/((\.0)+(-dev)?)+$/',
                    ''
                ),
                '/(\s)+/',
                ''
            );
        }

        if ($constraint instanceof MatchNoneConstraint) {
            return '<999,>999'; // impossible constraint - same as a "match nothing"
        }

        /** @psalm-suppress ImpureMethodCall besides memoization, {@see ConstraintInterface::__toString} is pure */
        return $constraint->__toString();
    }

    /** @throws LogicException */
    public function mergeWith(self $other): self
    {
        return self::fromString(
            self::constraintToString($this->constraint) 
            . '|'
            . self::constraintToString($other->constraint)
        );
    }
    
    /** 
     * @return -1|0|1
     *
     * @pure 
     */
    public static function sort(self $a, self $b): int
    {
        return self::sortConstraint($a->constraint, $b->constraint);
    }

    /** 
     * @return -1|0|1
     *
     * @pure 
     */
    private static function sortConstraint(ConstraintInterface $a, ConstraintInterface $b): int
    {
        if ($a instanceof MultiConstraint) {
            return self::sortConstraint($a->getConstraints()[0], $b);
        }

        if ($b instanceof MultiConstraint) {
            return self::sortConstraint($a, $b->getConstraints()[0]);
        }

        if ($a instanceof Constraint && $b instanceof Constraint) {
            $aVersion = $a->getVersion();
            $bVersion = $b->getVersion();

            if ($aVersion === $bVersion) {
                return 0;
            }

            /** @psalm-suppress ImpureMethodCall no state mutation occurs here */
            if (Semver::sort([$aVersion, $bVersion]) === [$bVersion, $aVersion]) {
                return 1;
            }

            return -1;
        }

        return 0;
    }
}
