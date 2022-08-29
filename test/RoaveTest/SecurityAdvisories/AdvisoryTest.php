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
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\PackageName;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Advisory}
 *
 * @covers \Roave\SecurityAdvisories\Advisory
 */
final class AdvisoryTest extends TestCase
{
    public function testFromArrayWithValidConfig(): void
    {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches'  => [
                '1.0.x' => [
                    'versions' => ['>=1.0', '<1.1'],
                ],
                '2.0.x' => [
                    'versions' => ['>=2.0', '<2.1'],
                ],
            ],
        ]);

        self::assertEquals(PackageName::fromName('foo/bar'), $advisory->package);
        self::assertSame('>=1,<1.1|>=2,<2.1', $advisory->getConstraint());

        $constraints = $advisory->getVersionConstraints();

        self::assertCount(2, $constraints);
        self::assertSame('>=1,<1.1', $constraints[0]->getConstraintString());
        self::assertSame('>=2,<2.1', $constraints[1]->getConstraintString());
    }

    public function testFromArrayWithComplexValidConfig(): void
    {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches'  => [
                '1.0.x' => [
                    'versions' => ['>=1.0-beta.3.4', '<1.1-alpha.4.5'],
                ],
                '2.0.x' => [
                    'versions' => ['>=2.0-rc.5', '<2.1-rc.6'],
                ],
            ],
        ]);

        self::assertEquals(PackageName::fromName('foo/bar'), $advisory->package);
        self::assertSame('>=1-beta.3.4,<1.1-alpha.4.5|>=2-rc.5,<2.1-rc.6', $advisory->getConstraint());

        $constraints = $advisory->getVersionConstraints();

        self::assertCount(2, $constraints);
        self::assertSame('>=1-beta.3.4,<1.1-alpha.4.5', $constraints[0]->getConstraintString());
        self::assertSame('>=2-rc.5,<2.1-rc.6', $constraints[1]->getConstraintString());
    }

    public function testFromArrayWithStringVersion(): void
    {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches'  => [
                '1.0.x' => ['versions' => '<1.1'],
                '2.0.x' => ['versions' => '<2.1'],
            ],
        ]);

        self::assertEquals(PackageName::fromName('foo/bar'), $advisory->package);
        self::assertSame('<1.1|<2.1', $advisory->getConstraint());

        $constraints = $advisory->getVersionConstraints();

        self::assertCount(2, $constraints);
        self::assertSame('<1.1', $constraints[0]->getConstraintString());
        self::assertSame('<2.1', $constraints[1]->getConstraintString());
    }

    public function testFromArrayWithComplexStringVersion(): void
    {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches'  => [
                '1.0.x' => ['versions' => '<1.1-beta.0.1'],
                '2.0.x' => ['versions' => '<2.1-beta.0.1'],
            ],
        ]);

        self::assertEquals(PackageName::fromName('foo/bar'), $advisory->package);
        self::assertSame('<1.1-beta.0.1|<2.1-beta.0.1', $advisory->getConstraint());

        $constraints = $advisory->getVersionConstraints();

        self::assertCount(2, $constraints);
        self::assertSame('<1.1-beta.0.1', $constraints[0]->getConstraintString());
        self::assertSame('<2.1-beta.0.1', $constraints[1]->getConstraintString());
    }

    public function testFromArrayWithWrongPackageName(): void
    {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo\bar',
            'branches'  => [],
        ]);

        self::assertEquals(PackageName::fromName('foo/bar'), $advisory->package);
    }

    /**
     * @param string[] $versionConstraint1
     * @param string[] $versionConstraint2
     *
     * @dataProvider unsortedBranchesProvider
     */
    public function testFromArrayGeneratesSortedResult(
        array $versionConstraint1,
        array $versionConstraint2,
        string $expected,
    ): void {
        $advisory = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches'  => [
                '2.0.x' => ['versions' => $versionConstraint2],
                '1.0.x' => ['versions' => $versionConstraint1],
            ],
        ]);

        self::assertSame($expected, $advisory->getConstraint());
    }

    /**
     * @psalm-return non-empty-list<array{
     *      non-empty-list<non-empty-string>,
     *      non-empty-list<non-empty-string>,
     *      non-empty-string
     * }>
     */
    public function unsortedBranchesProvider(): array
    {
        return [
            [
                ['>=1.0', '<1.1'],
                ['>=2.0', '<2.1'],
                '>=1,<1.1|>=2,<2.1',
            ],
            [
                ['>=1.0', '<1.1'],
                ['>=2.0'],
                '>=1,<1.1|>=2',
            ],
            [
                ['<1.1'],
                ['>=2.0', '<2.1'],
                '<1.1|>=2,<2.1',
            ],
            [
                ['<1.1-patch.5.6.0'],
                ['>=2.0', '<2.1'],
                '<1.1-patch.5.6|>=2,<2.1',
            ],
            [
                ['<1.1'],
                ['>=2.0-rc', '<2.1-beta.1'],
                '<1.1|>=2-rc,<2.1-beta.1',
            ],
            [
                ['>=2.0-a', '<2.1-a'],
                ['>=2.0-b', '<2.1-b'],
                '>=2-a,<2.1-a|>=2-b,<2.1-b',
            ],
        ];
    }
}
