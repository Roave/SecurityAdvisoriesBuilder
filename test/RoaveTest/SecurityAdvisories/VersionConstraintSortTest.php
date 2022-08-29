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
use Roave\SecurityAdvisories\VersionConstraintSort;

/**
 * Tests for {@see \Roave\SecurityAdvisories\VersionConstraintSort}
 *
 * @covers \Roave\SecurityAdvisories\VersionConstraintSort
 */
final class VersionConstraintSortTest extends TestCase
{
    /** @dataProvider comparedConstraints */
    public function testSorting(VersionConstraint $a, VersionConstraint $b, int $result): void
    {
        self::assertSame($result, (new VersionConstraintSort())->__invoke($a, $b));
        self::assertSame($result * -1, (new VersionConstraintSort())->__invoke($b, $a));
    }

    /** @psalm-return array<non-empty-string, array{VersionConstraint, VersionConstraint, int}> */
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
            ['>=1', '<=1', 0],
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
                 * @param array{0: non-empty-string, 1: non-empty-string, 2: int} $entry
                 *
                 * @returns non-empty-string
                 */
                static fn (array $entry): string => '"' . $entry[0] . '" <=> "' . $entry[1] . '"'
            ),
            Vec\map(
                $constraints,
                /**
                 * @param array{0: non-empty-string, 1: non-empty-string, 2: int} $entry
                 *
                 * @returns array{0: VersionConstraint, 1: VersionConstraint, 2: int}
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
