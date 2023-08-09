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

use PHPUnit\Framework\TestCase;
use Psl\Dict;
use Psl\Vec;
use Roave\SecurityAdvisories\VersionConstraint;
use UnexpectedValueException;

/** @covers \Roave\SecurityAdvisories\VersionConstraint */
final class VersionConstraintTest extends TestCase
{
    /** @dataProvider normalizableRangesProvider */
    public function testOperatesOnNormalizedRanges(string $originalRange, string $normalizedRange): void
    {
        self::assertSame($normalizedRange, VersionConstraint::fromString($originalRange)->getConstraintString());
    }

    /** @dataProvider complexRangesProvider */
    public function testFromRangeWithComplexRanges(string $stringConstraint, string $expectedNormalization): void
    {
        $constraint = VersionConstraint::fromString($stringConstraint);

        self::assertSame($expectedNormalization, $constraint->getConstraintString());
    }

    /** @dataProvider mergeableRangesProvider */
    public function testMergeWithMergeableRanges(
        string $constraintString1,
        string $constraintString2,
    ): void {
        $constraint1 = VersionConstraint::fromString($constraintString1);
        $constraint2 = VersionConstraint::fromString($constraintString2);

        $merged1 = $constraint1->mergeWith($constraint2);
        $merged2 = $constraint2->mergeWith($constraint1);

        self::assertEquals($merged1, $merged2);
    }

    /** @dataProvider strictlyOverlappingRangesProvider */
    public function testCanMergeWithMergeableRanges(string $range1, string $range2, string $expected): void
    {
        $constraint1 = VersionConstraint::fromString($range1);
        $constraint2 = VersionConstraint::fromString($range2);

        self::assertSame($expected, $constraint1->mergeWith($constraint2)->getConstraintString());
        self::assertSame($expected, $constraint2->mergeWith($constraint1)->getConstraintString());
    }

    /** @dataProvider nonStrictlyOverlappingRangesProvider */
    public function testNonMergeableRanges(string $range1, string $range2): void
    {
        $constraint1 = VersionConstraint::fromString($range1);
        $constraint2 = VersionConstraint::fromString($range2);

        $merged1 = $constraint1->mergeWith($constraint2)->getConstraintString();
        $merged2 = $constraint2->mergeWith($constraint1)->getConstraintString();

        $normalized1 = $constraint1->getConstraintString();
        $normalized2 = $constraint1->getConstraintString();

        self::assertNotEquals($normalized1, $merged1);
        self::assertNotEquals($normalized1, $merged2);
        self::assertNotEquals($normalized2, $merged1);
        self::assertNotEquals($normalized2, $merged2);
    }

    /** @psalm-return array<non-empty-string, array{non-empty-string, non-empty-string}> */
    public function complexRangesProvider(): array
    {
        $samples = [
            ['>1.2.3,<4.5.6,<7.8.9', '>1.2.3,<4.5.6'],
            ['1.2.3|4.5.6', '==1.2.3|==4.5.6'],
            ['1', '==1'],
            ['1|2', '==1|==2'],
            ['<1,<2', '<1'],
            ['>1,>2', '>2'],
            ['~2', '>=2,<3'],
            ['>1-a.2', '>1.0.0.0-alpha2'],
            ['<1-a.2', '<1.0.0.0-alpha2'],
            ['<1-a.2, >1-p.1.2', '<999,>999'], // impossible
            ['1-beta.2.0|1-rc.1.2.3', '==1.0.0.0-beta2|==1.0.0.0-RC1.2.3'],
        ];

        return Dict\associate(
            Vec\map(
                $samples,
                /**
                 * @param array{non-empty-string, non-empty-string} $sample
                 *
                 * @return non-empty-string
                 */
                static fn (array $sample) => $sample[0]
            ),
            $samples,
        );
    }

    /** @psalm-return array<non-empty-string, array{non-empty-string, non-empty-string, bool, bool}> */
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

        return Dict\associate(
            Vec\map(
                $entries,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string, ...} $entry
                 *
                 * @return non-empty-string
                 */
                static function (array $entry) {
                    return '((' . $entry[0] . ') ∩ (' . $entry[1] . ')) ≠ ∅';
                },
            ),
            $entries,
        );
    }

    /** @psalm-return array<non-empty-string, array{non-empty-string, non-empty-string}> */
    public function normalizableRangesProvider(): array
    {
        $samples = [
            ['<1', '<1'],
            ['<1-alpha', '<1.0.0.0-alpha'],
            ['<1-alpha.1.2', '<1.0.0.0-alpha1.2'],
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
            ['>1.2.3,<4.5.6', '>1.2.3,<4.5.6'],
            ['>=1.2.3,<4.5.6', '>=1.2.3,<4.5.6'],
            ['>1.2.3,<=4.5.6', '>1.2.3,<=4.5.6'],
            ['>=1.2.3,<=4.5.6', '>=1.2.3,<=4.5.6'],
            ['>  1.2.3  , < 4.5.6', '>1.2.3,<4.5.6'],
            ['>=  1.2.3  , <4.5.6', '>=1.2.3,<4.5.6'],
            ['> 1.2.3 , <=4.5.6', '>1.2.3,<=4.5.6'],
            ['>=1.2.3, <=4.5.6', '>=1.2.3,<=4.5.6'],
            ['>11.22.33,<44.55.66', '>11.22.33,<44.55.66'],
            ['>1,<2', '>1,<2'],
            ['>1-stable.1.2,<1.1-rc.1.2', '>1,<1.1.0.0-RC1.2-dev'],
            ['>1,<4|>2,<3', '>1,<4'],
            ['>1-alpha.1,<4-alpha.1|>2-beta.1,<3-beta.1', '>1.0.0.0-alpha1,<4.0.0.0-alpha1'],
        ];

        return Dict\associate(
            Vec\map(
                $samples,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string} $sample
                 *
                 * @return non-empty-string
                 */
                static fn ($sample) => $sample[0]
            ),
            $samples,
        );
    }

    /** @psalm-return array<non-empty-string, array{non-empty-string, non-empty-string, non-empty-string}> */
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
            ['>2-alpha.1,<3-alpha.1', '>2.1-alpha.1,<4-alpha.1', '>2.0.0.0-alpha1,<4.0.0.0-alpha1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<2.1-alpha.1', '>1.0.0.0-alpha1,<3.0.0.0-alpha1'],
            ['<3-alpha.1', '>1-alpha.1,<3.1-alpha.1', '<3.1.0.0-alpha1'],
            ['>3-alpha.1', '>2.1-alpha.1,<3.1-alpha.1', '>2.1.0.0-alpha1'],
            ['>1-alpha.1,<2-alpha.1', '>=2-alpha.1,<3-alpha.1', '>1.0.0.0-alpha1,<3.0.0.0-alpha1'],
            ['>1-alpha.1,<=2-alpha.1', '>2-alpha.1,<3-alpha.1', '>1.0.0.0-alpha1,<3.0.0.0-alpha1'],
            ['>1-alpha.1,<2-alpha.1', '>0.1-alpha.1,<=1-alpha.1', '>0.1.0.0-alpha1,<2.0.0.0-alpha1'],
            ['>=1-alpha.1,<2-alpha.1', '>0.1-alpha.1,<1-alpha.1', '>0.1.0.0-alpha1,<2.0.0.0-alpha1'],
            ['>1-alpha.1,<=2-alpha.1', '>2-alpha.1', '>1.0.0.0-alpha1'],
            ['>1-alpha.1,<2-alpha.1', '>=2-alpha.1', '>1.0.0.0-alpha1'],
            ['>1-alpha.1,<2-alpha.1', '<=1-alpha.1', '<2.0.0.0-alpha1'],
            ['>=1-alpha.1,<2-alpha.1', '<1-alpha.1', '<2.0.0.0-alpha1'],
            // test overlapping of flags
            ['>1-a,<1-rc', '>1-b,<1-stable', '>1.0.0.0-alpha,<1.0.0.0-RC-dev'],
            ['>1-a,<1-rc', '>1-b,<1-stable', '>1.0.0.0-alpha,<1.0.0.0-RC-dev'],
            ['>1-b,<1-stable', '>1-rc,<1', '<999,>999'],
            ['>1-rc,<1', '>1-stable,<1-patch', '>1,<1.0.0.0-patch'],
            ['>1-a,<1-rc', '>1-beta,<1-rc', '>1.0.0.0-alpha,<1.0.0.0-RC-dev'],
            // overlapping of stability numbers
            ['>1-a.1,<1-a.4', '>1-a.2,<1-a.5', '>1.0.0.0-alpha1,<1.0.0.0-alpha5'],
            ['>1-a.1.0.1.0,<1-a.4.1', '>1-a.1.0.2,<1-a.5.8', '>1.0.0.0-alpha1.0.1,<1.0.0.0-alpha5.8'],
        ];

        return Dict\associate(
            Vec\map(
                $entries,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string, 2: non-empty-string} $entry
                 *
                 * @return non-empty-string
                 */
                static function (array $entry) {
                    return '((' . $entry[0] . ') ∪ (' . $entry[1] . ')) = (' . $entry[2] . ')';
                },
            ),
            $entries,
        );
    }

    /** @psalm-return array<non-empty-string, array{non-empty-string, non-empty-string}> */
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
            ['>2-alpha.1,<3-alpha.1', '>3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>=3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<=3-alpha.1', '>3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<=3-alpha.1', '>=3-alpha.1,<4-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<2-alpha.1'],
            ['>2-alpha.1,<3-alpha.1', '>1-alpha.1,<=2-alpha.1'],
            ['>=2-alpha.1,<3-alpha.1', '>1-alpha.1,<2-alpha.1'],
            ['>=2-alpha.1,<3-alpha.1', '>1-alpha.1,<=2-alpha.1'],
            ['>1-p, <1-a', '>1-b,<1-rc'],
        ];

        return Dict\associate(
            Vec\map(
                $entries,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string} $entry
                 *
                 * @return non-empty-string
                 */
                static function (array $entry): string {
                    return '((' . $entry[0] . ') ∩ (' . $entry[1] . ')) = ∅';
                },
            ),
            $entries,
        );
    }

    /** @dataProvider invalidRangesProvider */
    public function testWillRejectInvalidVersionConstraints(string $constraint): void
    {
        $this->expectException(UnexpectedValueException::class);

        VersionConstraint::fromString($constraint);
    }

    /** @psalm-return non-empty-list<array{non-empty-string}> */
    public function invalidRangesProvider(): array
    {
        return [
            ['<3.1.33-dev-4'],
            ['< 3.1.33-dev-4'],
            ['>11.22.33.44.55.66.77,<44.55.66.77.88.99.1010'],
            ['<=1.0.3.0.5.0-beta.0.5.0.0'],
            ['>1a2b3,<4c5d6'],
            ['foo,bar'],
            ['foo'],
            ['bar'],
        ];
    }

    /** @dataProvider comparedConstraints */
    public function testSorting(VersionConstraint $a, VersionConstraint $b, int $result): void
    {
        self::assertSame($result, VersionConstraint::sort($a, $b));
        self::assertSame($result * -1, VersionConstraint::sort($b, $a));
    }

    /** @psalm-return array<non-empty-string, array{VersionConstraint, VersionConstraint, -1|0|1}> */
    public function comparedConstraints(): array
    {
        $constraints = [
            ['>=1', '>=1', 0],
            ['<=1', '<=1', 0],
            ['>=1,<=2', '>=1,<=2', 0],
            ['>=1,<=2', '>=3,<=4', -1],
            ['>=3,<=4', '>=1,<=2', 1],
            ['<=1', '<=2', -1],
            ['<=2', '<=1', 1],
            ['>=1', '<=1', -1],
            ['>=1-dev', '<=1', -1],
            ['>=2', '<=1', 1],
            ['>=1', '<=2', -1],
            ['>=1,<=2,>3', '>=1,<=2', 0],
            ['>=1-alpha.9', '>=1-alpha.9', 0],
            ['<=1-alpha.9', '<=1-alpha.9', 0],
            ['>=1-alpha.9,<=2-alpha.9', '>=1-alpha.9,<=2-alpha.9', 0],
            ['>=1-alpha.9,<=2-alpha.9', '>=3-alpha.9,<=4-alpha.9', -1],
            ['>=3-alpha.9,<=4-alpha.9', '>=1-alpha.9,<=2-alpha.9', 1],
            ['<=1-alpha.9', '<=2-alpha.9', -1],
            ['<=2-alpha.9', '<=1-alpha.9', 1],
            ['>=1-alpha.9', '<=1-alpha.9', 0],
            ['>=2-alpha.9', '<=1-alpha.9', 1],
            ['>=1-alpha.9', '<=2-alpha.9', -1],
            ['>=1-alpha.9,<=2-alpha.9,>3-alpha.9', '>=1-alpha.9,<=2-alpha.9', 0],
        ];

        return Dict\associate(
            Vec\map(
                $constraints,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string, 2: -1|0|1} $entry
                 *
                 * @returns non-empty-string
                 */
                static fn (array $entry): string => '"' . $entry[0] . '" <=> "' . $entry[1] . '"'
            ),
            Vec\map(
                $constraints,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string, 2: -1|0|1} $entry
                 *
                 * @returns array{0: VersionConstraint, 1: VersionConstraint, 2: -1|0|1}
                 */
                static fn (array $entry): array => [
                    VersionConstraint::fromString($entry[0]),
                    VersionConstraint::fromString($entry[1]),
                    $entry[2],
                ]
            ),
        );
    }
}
