<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

declare(strict_types=1);

namespace RoaveTest\SecurityAdvisories;

use LogicException;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use Roave\SecurityAdvisories\Version;
use Roave\SecurityAdvisories\VersionConstraint;

use function array_column;
use function array_map;
use function Safe\array_combine;
use function Safe\preg_match;
use function var_export;

/**
 * Tests for {@see \Roave\SecurityAdvisories\VersionConstraint}
 *
 * @covers \Roave\SecurityAdvisories\VersionConstraint
 */
final class VersionConstraintTest extends TestCase
{
    /**
     * @dataProvider closedRangesProvider
     */
    public function testFromRange(string $stringConstraint): void
    {
        $constraint = VersionConstraint::fromString($stringConstraint);

        self::assertInstanceOf(Version::class, $constraint->getLowerBound());
        self::assertInstanceOf(Version::class, $constraint->getUpperBound());

        $constraintAsString = $constraint->getConstraintString();

        self::assertSame((bool) preg_match('/>=/', $stringConstraint), $constraint->isLowerBoundIncluded());
        self::assertSame((bool) preg_match('/<=/', $stringConstraint), $constraint->isUpperBoundIncluded());
        self::assertStringMatchesFormat('%A' . $constraint->getLowerBound()->getVersion() . '%A', $constraintAsString);
        self::assertStringMatchesFormat('%A' . $constraint->getUpperBound()->getVersion() . '%A', $constraintAsString);
    }

    /**
     * @dataProvider normalizableRangesProvider
     */
    public function testOperatesOnNormalizedRanges(string $originalRange, string $normalizedRange): void
    {
        self::assertSame($normalizedRange, VersionConstraint::fromString($originalRange)->getConstraintString());
    }

    /**
     * @dataProvider leftOpenEndedRangeProvider
     */
    public function testLeftOpenEndedRange(string $leftOpenedRange): void
    {
        $constraint = VersionConstraint::fromString($leftOpenedRange);

        self::assertSame($leftOpenedRange, $constraint->getConstraintString());
        self::assertNull($constraint->getLowerBound());
        self::assertInstanceOf(Version::class, $constraint->getUpperBound());
        self::assertFalse($constraint->isLowerBoundIncluded());
        self::assertFalse($constraint->isUpperBoundIncluded());
    }

    public function testRightOpenEndedRange(): void
    {
        $constraint = VersionConstraint::fromString('>1');

        self::assertTrue($constraint->isSimpleRangeString());
        self::assertSame('>1', $constraint->getConstraintString());
        self::assertNull($constraint->getUpperBound());
        self::assertInstanceOf(Version::class, $constraint->getLowerBound());
        self::assertFalse($constraint->isLowerBoundIncluded());
        self::assertFalse($constraint->isUpperBoundIncluded());
    }

    public function testLeftOpenEndedRangeBoundIncluded(): void
    {
        $constraint = VersionConstraint::fromString('<=1');

        self::assertTrue($constraint->isSimpleRangeString());
        self::assertSame('<=1', $constraint->getConstraintString());
        self::assertNull($constraint->getLowerBound());
        self::assertInstanceOf(Version::class, $constraint->getUpperBound());
        self::assertFalse($constraint->isLowerBoundIncluded());
        self::assertTrue($constraint->isUpperBoundIncluded());
    }

    public function testRightOpenEndedRangeBoundIncluded(): void
    {
        $constraint = VersionConstraint::fromString('>=1');

        self::assertTrue($constraint->isSimpleRangeString());
        self::assertSame('>=1', $constraint->getConstraintString());
        self::assertNull($constraint->getUpperBound());
        self::assertInstanceOf(Version::class, $constraint->getLowerBound());
        self::assertTrue($constraint->isLowerBoundIncluded());
        self::assertFalse($constraint->isUpperBoundIncluded());
    }

    /**
     * @dataProvider complexRangesProvider
     */
    public function testFromRangeWithComplexRanges(string $stringConstraint): void
    {
        $constraint = VersionConstraint::fromString($stringConstraint);

        self::assertSame($stringConstraint, $constraint->getConstraintString());
    }

    public function testContainsWithMatchingRanges(): void
    {
        $constraint1 = VersionConstraint::fromString('>1.2.3,<4.5.6');
        $constraint2 = VersionConstraint::fromString('>1.2.4,<4.5.5');

        self::assertTrue($this->callContains($constraint1, $constraint2));
        self::assertFalse($this->callContains($constraint2, $constraint1));

        $constraint1 = VersionConstraint::fromString('>1.2.3-alpha.1,<4.5.6-beta.3.4');
        $constraint2 = VersionConstraint::fromString('>1.2.4-rc,<4.5.5-patch.5.6.7.8');

        self::assertTrue($this->callContains($constraint1, $constraint2));
        self::assertFalse($this->callContains($constraint2, $constraint1));
    }

    public function testCannotCompareComplexRanges(): void
    {
        $constraint1 = VersionConstraint::fromString('1|2');
        $constraint2 = VersionConstraint::fromString('1|2|3');

        self::assertFalse($this->callContains($constraint1, $constraint2));
        self::assertFalse($this->callContains($constraint2, $constraint1));
    }

    /**
     * @dataProvider rangesForComparisonProvider
     */
    public function testContainsWithRanges(
        string $constraintString1,
        string $constraintString2,
        bool $constraint1ContainsConstraint2,
        bool $constraint2ContainsConstraint1
    ): void {
        $constraint1 = VersionConstraint::fromString($constraintString1);
        $constraint2 = VersionConstraint::fromString($constraintString2);

        self::assertSame($constraint1ContainsConstraint2, $this->callContains($constraint1, $constraint2));
        self::assertSame($constraint2ContainsConstraint1, $this->callContains($constraint2, $constraint1));
    }

    /**
     * @dataProvider mergeableRangesProvider
     */
    public function testCanMergeWithContainedRanges(
        string $constraintString1,
        string $constraintString2,
        bool $constraint1ContainsConstraint2,
        bool $constraint2ContainsConstraint1
    ): void {
        $constraint1 = VersionConstraint::fromString($constraintString1);
        $constraint2 = VersionConstraint::fromString($constraintString2);
        $expectation = $constraint2ContainsConstraint1 || $constraint1ContainsConstraint2;

        self::assertSame($expectation, $constraint1->canMergeWith($constraint2));
    }

    /**
     * @dataProvider mergeableRangesProvider
     */
    public function testMergeWithMergeableRanges(
        string $constraintString1,
        string $constraintString2,
        bool $constraint1ContainsConstraint2,
        bool $constraint2ContainsConstraint1
    ): void {
        $constraint1 = VersionConstraint::fromString($constraintString1);
        $constraint2 = VersionConstraint::fromString($constraintString2);

        if (! ($constraint2ContainsConstraint1 || $constraint1ContainsConstraint2)) {
            $this->expectException(LogicException::class);
        }

        $merged1 = $constraint1->mergeWith($constraint2);
        $merged2 = $constraint2->mergeWith($constraint1);

        self::assertEquals($merged1, $merged2);

        self::assertTrue($this->callContains($merged1, $constraint1));
        self::assertTrue($this->callContains($merged1, $constraint2));
    }

    /**
     * @dataProvider strictlyOverlappingRangesProvider
     */
    public function testCanMergeWithMergeableRanges(string $range1, string $range2, string $expected): void
    {
        $constraint1 = VersionConstraint::fromString($range1);
        $constraint2 = VersionConstraint::fromString($range2);

        self::assertSame($expected, $constraint1->mergeWith($constraint2)->getConstraintString());
        self::assertSame($expected, $constraint2->mergeWith($constraint1)->getConstraintString());
    }

    /**
     * @dataProvider nonStrictlyOverlappingRangesProvider
     */
    public function testNonMergeableRanges(string $range1, string $range2): void
    {
        $constraint1 = VersionConstraint::fromString($range1);
        $constraint2 = VersionConstraint::fromString($range2);

        self::assertFalse($this->callOverlapsWith($constraint1, $constraint2));
        self::assertFalse($this->callOverlapsWith($constraint2, $constraint1));

        $this->expectException(LogicException::class);

        $this->callMergeWithOverlapping($constraint1, $constraint2);
    }

    /**
     * @return string[][]
     */
    public function closedRangesProvider(): array
    {
        $matchedRanges = [
            ['>1.2.3,<4.5.6'],
            ['>=1.2.3,<4.5.6'],
            ['>1.2.3,<=4.5.6'],
            ['>=1.2.3,<=4.5.6'],
            ['>  1.2.3  , < 4.5.6'],
            ['>=  1.2.3  , <4.5.6'],
            ['> 1.2.3 , <=4.5.6'],
            ['>=1.2.3, <=4.5.6'],
            ['>11.22.33,<44.55.66'],
            ['>11.22.33.44.55.66.77,<44.55.66.77.88.99.1010'],
            ['>1,<2'],
            ['>1-stable.1.2,<1-rc.1.2'],
        ];

        return array_combine(
            array_column($matchedRanges, 0),
            $matchedRanges
        );
    }

    /**
     * @return string[][]
     */
    public function complexRangesProvider(): array
    {
        return $this->dataProviderFirstValueAsProviderKey([
            ['>1.2.3,<4.5.6,<7.8.9'],
            ['1.2.3|4.5.6'],
            ['1'],
            ['1|2'],
            ['<1,<2'],
            ['>1,>2'],
            ['~2'],
            ['>1a2b3,<4c5d6'],
            ['>1-a.2'],
            ['<1-a.2'],
            ['<1-a.2, >1-p.1.2'],
            ['1-beta.2.0|1-rc.1.2.3'],
        ]);
    }

    /**
     * @return string[][]|bool[][]
     *
     *  - range1
     *  - range2
     *  - range1 contains range2
     *  - range2 contains range1
     */
    public function rangesForComparisonProvider(): array
    {
        $entries = [
            ['>1,<2', '>1,<2', true, true],
            ['>1,<2', '>1.1,<2', true, false],
            ['>1,<2', '>3,<4', false, false],
            ['>1.1,<2.1', '>1.2,<2', true, false],
            ['>100,<200', '>1.0.0,<2.0.0', false, false],
            ['>1.10,<2', '>1.100,<2', true, false],
            ['>1,<2.10', '>1,<2.100', false, true],
            ['>1.0,<2', '>1,<2', true, true],
            ['>1,<2.0', '>1,<2', true, true],
            ['>1.0.0,<2', '>1,<2', true, true],
            ['>1,<2.0.0', '>1,<2', true, true],
            ['>=1,<2', '>1,<2', true, false],
            ['>=1,<2', '>=1,<2', true, true],
            ['>1,<=2', '>1,<2', true, false],
            ['>1,<=2', '>1,<=2', true, true],
            ['>=1,<=2', '>1,<2', true, false],
            ['>=1,<=2', '>=1,<=2', true, true],
            ['>=1,<=2', '>=1,<=2', true, true],
            ['>=1', '>=1,<2', true, false],
            ['>=1', '>1,<2', true, false],
            ['>1', '>=1,<2', false, false], // this is mergeable, but not updated in tests
            ['<=2', '>1,<=2', true, false],
            ['<=2', '>1,<2', true, false],
            ['<2', '>1,<=2', false, false], // this is mergeable, but not updated in tests
            ['<2', '<2', true, true],
            ['<=2', '<=2', true, true],
            ['<=2', '<2', true, false],
            ['<=2', '<1', true, false],
            ['<=2', '<3', false, true],
            ['>2', '>2', true, true],
            ['>=2', '>=2', true, true],
            ['>=2', '>2', true, false],
            ['>=2', '>1', false, true],
            ['>=2', '>3', true, false],
            // stabilities
            ['>1-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2-beta.1', '>1.1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<2-beta.1', '>3-beta.1,<4-beta.1', false, false],
            ['>1.1-beta.1,<2.1-beta.1', '>1.2-beta.1,<2-beta.1', true, false],
            ['>100-beta.1,<200-beta.1', '>1.0.0-beta.1,<2.0.0-beta.1', false, false],
            ['>1.10-beta.1,<2-beta.1', '>1.100-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<2.10-beta.1', '>1-beta.1,<2.100-beta.1', false, true],
            ['>1.0-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2.0-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1.0.0-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2.0.0-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>=1-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1,<2-beta.1', '>=1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<=2-beta.1', '>1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1,<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1,<=2-beta.1', '>=1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1,<=2-beta.1', '>=1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1', '>=1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1', '>=1-beta.1,<2-beta.1', false, false],
            ['<=2-beta.1', '>1-beta.1,<=2-beta.1', true, false],
            ['<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['<2-beta.1', '>1-beta.1,<=2-beta.1', false, false],
            ['<2-beta.1', '<2-beta.1', true, true],
            ['<=2-beta.1', '<=2-beta.1', true, true],
            ['<=2-beta.1', '<2-beta.1', true, false],
            ['<=2-beta.1', '<1-beta.1', true, false],
            ['<=2-beta.1', '<3-beta.1', false, true],
            ['>2-beta.1', '>2-beta.1', true, true],
            ['>=2-beta.1', '>=2-beta.1', true, true],
            ['>=2-beta.1', '>2-beta.1', true, false],
            ['>=2-beta.1', '>1-beta.1', false, true],
            ['>=2-beta.1', '>3-beta.1', true, false],
            ['>1-stable', '<1-stable', false, false],
            ['>1-stable', '>1-stable', true, true],

            ['>1-stable.1.2.3', '>1-stable.1.2.3.4', true, false],
            ['>=1-stable.1.2.3', '>=1-stable.1.2.3.4', true, false],
            ['>1-stable.1.2.3', '<1-stable.1.2.3.4', false, false],
            ['>=1-stable.1.2.3', '<=1-stable.1.2.3.4', false, false],
            ['<1-stable.1.2.3', '<1-stable.1.2.3.4', false, true],
            ['<=1-stable.1.2.3', '<=1-stable.1.2.3.4', false, true],
            ['<1-stable.1.2.3', '>1-stable.1.2.3.4', false, false],
            ['<=1-stable.1.2.3', '>=1-stable.1.2.3.4', false, false],

        ];

        return array_combine(
            array_map(
                static function (array $entry) {
                    return '(∀ x ∈ (' . $entry[0] . '): x ∈ (' . $entry[1] . ')) = ' . var_export($entry[2], true);
                },
                $entries
            ),
            $entries
        );
    }

    /**
     * @return string[][]|bool[][]
     */
    public function mergeableRangesProvider(): array
    {
        $entries = [
            ['>1,<2', '>1,<2', true, true],
            ['>1,<2', '>1.1,<2', true, false],
            ['>1,<2', '>3,<4', false, false],
            ['>1.1,<2.1', '>1.2,<2', true, false],
            ['>100,<200', '>1.0.0,<2.0.0', false, false],
            ['>1.10,<2', '>1.100,<2', true, false],
            ['>1,<2.10', '>1,<2.100', false, true],
            ['>1.0,<2', '>1,<2', true, true],
            ['>1,<2.0', '>1,<2', true, true],
            ['>1.0.0,<2', '>1,<2', true, true],
            ['>1,<2.0.0', '>1,<2', true, true],
            ['>=1,<2', '>1,<2', true, false],
            ['>=1,<2', '>=1,<2', true, true],
            ['>1,<=2', '>1,<2', true, false],
            ['>1,<=2', '>1,<=2', true, true],
            ['>=1,<=2', '>1,<2', true, false],
            ['>=1,<=2', '>=1,<=2', true, true],
            ['>=1,<=2', '>=1,<=2', true, true],
            ['>=1', '>=1,<2', true, false],
            ['>=1', '>1,<2', true, false],
            ['>1', '>=1,<2', true, true],
            ['<=2', '>1,<=2', true, false],
            ['<=2', '>1,<2', true, false],
            ['<2', '>1,<=2', true, true],
            ['<2', '<2', true, true],
            ['<=2', '<=2', true, true],
            ['<=2', '<2', true, false],
            ['<=2', '<1', true, false],
            ['<=2', '<3', false, true],
            ['>2', '>2', true, true],
            ['>=2', '>=2', true, true],
            ['>=2', '>2', true, false],
            ['>=2', '>1', false, true],
            ['>=2', '>3', true, false],
            ['>1.1,<2.1', '>1.2,<2.0', true, false],
            ['>1.2,<2.0', '>1.1,<2.1', true, false],
            ['>1,<2,>3', '>1,<2', false, false],

            ['>1-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2-beta.1', '>1.1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<2-beta.1', '>3-beta.1,<4-beta.1', false, false],
            ['>1.1-beta.1,<2.1-beta.1', '>1.2-beta.1,<2-beta.1', true, false],
            ['>100-beta.1,<200-beta.1', '>1.0.0-beta.1,<2.0.0-beta.1', false, false],
            ['>1.10-beta.1,<2-beta.1', '>1.100-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<2.10-beta.1', '>1-beta.1,<2.100-beta.1', false, true],
            ['>1.0-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2.0-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1.0.0-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<2.0.0-beta.1', '>1-beta.1,<2-beta.1', true, true],
            ['>=1-beta.1,<2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1,<2-beta.1', '>=1-beta.1,<2-beta.1', true, true],
            ['>1-beta.1,<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1,<=2-beta.1', '>1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1,<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1,<=2-beta.1', '>=1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1,<=2-beta.1', '>=1-beta.1,<=2-beta.1', true, true],
            ['>=1-beta.1', '>=1-beta.1,<2-beta.1', true, false],
            ['>=1-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['>1-beta.1', '>=1-beta.1,<2-beta.1', true, true],
            ['<=2-beta.1', '>1-beta.1,<=2-beta.1', true, false],
            ['<=2-beta.1', '>1-beta.1,<2-beta.1', true, false],
            ['<2-beta.1', '>1-beta.1,<=2-beta.1', true, true],
            ['<2-beta.1', '<2-beta.1', true, true],
            ['<=2-beta.1', '<=2-beta.1', true, true],
            ['<=2-beta.1', '<2-beta.1', true, false],
            ['<=2-beta.1', '<1-beta.1', true, false],
            ['<=2-beta.1', '<3-beta.1', false, true],
            ['>2-beta.1', '>2-beta.1', true, true],
            ['>=2-beta.1', '>=2-beta.1', true, true],
            ['>=2-beta.1', '>2-beta.1', true, false],
            ['>=2-beta.1', '>1-beta.1', false, true],
            ['>=2-beta.1', '>3-beta.1', true, false],
            ['>1.1-beta.1,<2.1-beta.1', '>1.2-beta.1,<2.0-beta.1', true, false],
            ['>1.2-beta.1,<2.0-beta.1', '>1.1-beta.1,<2.1-beta.1', true, false],
            ['>1-beta.1,<2-beta.1,>3-beta.1', '>1-beta.1,<2-beta.1', false, false],

            ['>1-beta,<1-beta', '>1-beta,<1-beta', true, true],
            ['>1-a,<1-stable', '>1-b,<1-rc', true, false], // first contains second
            ['>1-a,<1-b', '>1-rc,<1-stable', false, false], // totally not overlapping versions
            // patch versions
            ['>1-p,<1-p', '>1-p,<1-p', true, true],
            ['>1-a,<1-p', '>1-a,<1-b', true, false],
            ['>1,<1-p', '>1-a,<1-b', false, false],
        ];

        return array_combine(
            array_map(
                static function (array $entry) {
                    return '((' . $entry[0] . ') ∩ (' . $entry[1] . ')) ≠ ∅';
                },
                $entries
            ),
            $entries
        );
    }

    /**
     * @return string[][]
     */
    public function normalizableRangesProvider(): array
    {
        return $this->dataProviderFirstValueAsProviderKey([
            ['>1.0,<2.0', '>1,<2'],
            ['>=1.0,<2.0', '>=1,<2'],
            ['>1.0,<=2.0', '>1,<=2'],
            ['>=1.0,<=2.0', '>=1,<=2'],
            ['>1.0', '>1'],
            ['>=1.0', '>=1'],
            ['<1.0', '<1'],
            ['<=1.0', '<=1'],
            ['>1.0,<2.0', '>1,<2'],
            ['>=1.0,<2.0', '>=1,<2'],
            ['>1.0,<=2.0', '>1,<=2'],
            ['>=1.0,<=2.0', '>=1,<=2'],
            ['>1.0', '>1'],
            ['>=1.0', '>=1'],
            ['<1.0', '<1'],
            ['<=1.0', '<=1'],
            ['<=1.0.3.0.5.0-beta.0.5.0.0', '<=1.0.3.0.5-beta.0.5'],
        ]);
    }

    /**
     * @return string[][]
     */
    public function strictlyOverlappingRangesProvider(): array
    {
        $entries = [
            ['>2,<3', '>2.1,<4', '>2,<4'],
            ['>2,<3', '>1,<2.1', '>1,<3'],
            ['<3', '>1,<3.1', '<3.1'],
            ['>3', '>2.1,<3.1', '>2.1'],
            ['>1,<2', '>=2,<3', '>1,<3'],
            ['>1,<=2', '>2,<3', '>1,<3'],
            ['>1,<2', '>0.1,<=1', '>0.1,<2'],
            ['>=1,<2', '>0.1,<1', '>0.1,<2'],
            ['>1,<=2', '>2', '>1'],
            ['>1,<2', '>=2', '>1'],
            ['>1,<2', '<=1', '<2'],
            ['>=1,<2', '<1', '<2'],
            // just to make sure we are compatible
            ['>2-alpha.1,<3-alpha.1', '>2.1-alpha.1,<4-alpha.1', '>2-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<2.1-alpha.1', '>1-alpha.1,<3-alpha.1'],
            ['<3-alpha.1', '>1-alpha.1,<3.1-alpha.1', '<3.1-alpha.1'],
            ['>3-alpha.1', '>2.1-alpha.1,<3.1-alpha.1', '>2.1-alpha.1'],
            ['>1-alpha.1,<2-alpha.1', '>=2-alpha.1,<3-alpha.1', '>1-alpha.1,<3-alpha.1'],
            ['>1-alpha.1,<=2-alpha.1', '>2-alpha.1,<3-alpha.1', '>1-alpha.1,<3-alpha.1'],
            ['>1-alpha.1,<2-alpha.1', '>0.1-alpha.1,<=1-alpha.1', '>0.1-alpha.1,<2-alpha.1'],
            ['>=1-alpha.1,<2-alpha.1', '>0.1-alpha.1,<1-alpha.1', '>0.1-alpha.1,<2-alpha.1'],
            ['>1-alpha.1,<=2-alpha.1', '>2-alpha.1', '>1-alpha.1'],
            ['>1-alpha.1,<2-alpha.1', '>=2-alpha.1', '>1-alpha.1'],
            ['>1-alpha.1,<2-alpha.1', '<=1-alpha.1', '<2-alpha.1'],
            ['>=1-alpha.1,<2-alpha.1', '<1-alpha.1', '<2-alpha.1'],
            // test overlapping of flags
            ['>1-a,<1-rc', '>1-b,<1-stable', '>1-a,<1-stable'],
            ['>1-b,<1-stable', '>1-rc,<1', '>1-b,<1'],
            ['>1-rc,<1', '>1-stable,<1-patch', '>1-rc,<1-patch'],
            ['>1-a,<1-rc', '>1-beta,<1-rc', '>1-a,<1-rc'],
            // overlapping of stability numbers
            ['>1-a.1,<1-a.4', '>1-a.2,<1-a.5', '>1-a.1,<1-a.5'],
            ['>1-a.1.0.1.0,<1-a.4.1', '>1-a.1.0.2,<1-a.5.8', '>1-a.1.0.1,<1-a.5.8'],
        ];

        return array_combine(
            array_map(
                static function (array $entry) {
                    return '((' . $entry[0] . ') ∪ (' . $entry[1] . ')) = (' . $entry[2] . ')';
                },
                $entries
            ),
            $entries
        );
    }

    /**
     * @return string[][]
     */
    public function nonStrictlyOverlappingRangesProvider(): array
    {
        $entries = [
            ['>2,<3', '>3,<4'],
            ['>2,<3', '>=3,<4'],
            ['>2,<=3', '>3,<4'],
            ['>2,<=3', '>=3,<4'],
            ['>2,<3', '>1,<2'],
            ['>2,<3', '>1,<=2'],
            ['>=2,<3', '>1,<2'],
            ['>=2,<3', '>1,<=2'],
            ['foo', '>1,<2'],
            ['>2,<3', 'foo'],
            ['bar', 'foo'],
            ['>1,<4', '>2,<3'], // note: containing, not overlapping.
            ['>2-alpha.1,<3-alpha.1', '>3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>=3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<=3-alpha.1', '>3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<=3-alpha.1', '>=3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<2-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<=2-alpha.1'],
            ['>=2-alpha.1,<3-alpha.1', '>1-alpha.1,<2-alpha.1'],
            ['>=2-alpha.1,<3-alpha.1', '>1-alpha.1,<=2-alpha.1'],
            ['foo', '>1-alpha.1,<2-alpha.1'],
            ['>2-alpha.1,<3', 'foo'],
            ['bar', 'foo'],
            ['>1-p, <1-a', '>1-b,<1-rc'],
            ['>1-alpha.1,<4-alpha.1', '>2-beta.1,<3-beta.1'], // note: containing, not overlapping.
        ];

        return array_combine(
            array_map(
                static function (array $entry) {
                    return '((' . $entry[0] . ') ∩ (' . $entry[1] . ')) = ∅';
                },
                $entries
            ),
            $entries
        );
    }

    /**
     * @param mixed[][] $entries
     *
     * @return mixed[][]
     */
    private function dataProviderFirstValueAsProviderKey(array $entries): array
    {
        return array_combine(
            array_column($entries, 0),
            $entries
        );
    }

    private function callContains(VersionConstraint $versionConstraint, VersionConstraint $other): bool
    {
        $containsReflection = new ReflectionMethod($versionConstraint, 'contains');

        $containsReflection->setAccessible(true);

        return $containsReflection->invoke($versionConstraint, $other);
    }

    private function callOverlapsWith(VersionConstraint $versionConstraint, VersionConstraint $other): bool
    {
        $overlapsWithReflection = new ReflectionMethod($versionConstraint, 'overlapsWith');

        $overlapsWithReflection->setAccessible(true);

        return $overlapsWithReflection->invoke($versionConstraint, $other);
    }

    private function callMergeWithOverlapping(
        VersionConstraint $versionConstraint,
        VersionConstraint $other
    ): VersionConstraint {
        $mergeWithOverlappingReflection = new ReflectionMethod($versionConstraint, 'mergeWithOverlapping');

        $mergeWithOverlappingReflection->setAccessible(true);

        return $mergeWithOverlappingReflection->invoke($versionConstraint, $other);
    }

    /**
     * @return string[][]
     */
    public function leftOpenEndedRangeProvider(): array
    {
        return [
            ['<1'],
            ['<1-alpha'],
            ['<1-alpha.1.2'],
        ];
    }
}
