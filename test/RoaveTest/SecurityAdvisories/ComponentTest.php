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
use Roave\SecurityAdvisories\Component;
use Roave\SecurityAdvisories\PackageName;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Component}
 *
 * @covers \Roave\SecurityAdvisories\Component
 */
final class ComponentTest extends TestCase
{
    public function testFromMultipleAdvisories(): void
    {
        $advisory1 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    'versions' => ['>=1.0-beta.1.1', '<1.1-beta.1.1'],
                ],
                '2.0.x' => [
                    'versions' => ['>=2.0-beta.1.1', '<2.1-beta.1.1'],
                ],
            ],
        ]);
        $advisory2 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    'versions' => ['>=3.0-beta.1.1', '<3.1-beta.1.1'],
                ],
                '2.0.x' => [
                    'versions' => ['>=4.0-beta.1.1', '<4.1-beta.1.1'],
                ],
            ],
        ]);

        $component = new Component(PackageName::fromName('foo/bar'), $advisory1, $advisory2);

        $expected = '>=1-beta.1.1,<1.1-beta.1.1|>=2-beta.1.1,<2.1-beta.1.1|' .
            '>=3-beta.1.1,<3.1-beta.1.1|>=4-beta.1.1,<4.1-beta.1.1';
        self::assertSame($expected, $component->getConflictConstraint());
        self::assertEquals(PackageName::fromName('foo/bar'), $component->name);
    }

    public function testDeDuplicatesOverlappingAdvisories(): void
    {
        $advisory1 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    'versions' => ['>=1.0', '<1.1'],
                ],
                '2.0.x' => [
                    'versions' => ['>=2.0', '<2.1'],
                ],
            ],
        ]);
        $advisory2 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    // this should not appear, as it is included in a previous advisory
                    'versions' => ['>=1.0.1', '<1.0.99'],
                ],
                '2.0.x' => [
                    // this should not appear, as it is included in a previous advisory
                    'versions' => ['>=2.0.1', '<2.1'],
                ],
                '3.0.x' => [
                    // this should appear, as it is not covered by previous advisories
                    'versions' => ['>=3.0', '<3.1'],
                ],
            ],
        ]);
        $advisory3 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '3.0.x' => [
                    // this should not appear, as it is included in the second advisory
                    'versions' => ['>=3.0.1', '<3.0.99'],
                ],
            ],
        ]);

        $component = new Component(PackageName::fromName('foo/bar'), $advisory1, $advisory2, $advisory3);

        self::assertSame('>=1,<1.1|>=2,<2.1|>=3,<3.1', $component->getConflictConstraint());
        self::assertEquals(PackageName::fromName('foo/bar'), $component->name);
    }

    public function testDeDuplicatesOverlappingComplexAdvisories(): void
    {
        $advisory1 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    'versions' => ['>=1.0-p.1.1.2', '<1.1-b.1.1.3'],
                ],
                '2.0.x' => [
                    'versions' => ['>=2.0-rc', '<2.1-p'],
                ],
            ],
        ]);
        $advisory2 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '1.0.x' => [
                    // this should not appear, as it is included in a previous advisory
                    'versions' => ['>=1.0-p.1.1.3', '<1.1-b.1.1.2'],
                ],
                '2.0.x' => [
                    // this should not appear, as it is included in a previous advisory
                    'versions' => ['>=2.0.1', '<2.1'],
                ],
                '3.0.x' => [
                    // this should appear, as it is not covered by previous advisories
                    'versions' => ['>=3.0-stable.5', '<3.1'],
                ],
            ],
        ]);
        $advisory3 = Advisory::fromArrayData([
            'reference' => 'composer://foo/bar',
            'branches' => [
                '3.0.x' => [
                    // this should not appear, as it is included in the second advisory
                    'versions' => ['>=3.0.1', '<3.0.99'],
                ],
            ],
        ]);

        $component = new Component(PackageName::fromName('foo/bar'), $advisory1, $advisory2, $advisory3);

        $expected = '>=1-p.1.1.2,<1.1-b.1.1.3|>=2-rc,<2.1-p|>=3-stable.5,<3.1';
        self::assertSame($expected, $component->getConflictConstraint());
        self::assertEquals(PackageName::fromName('foo/bar'), $component->name);
    }

    public function testSortAdvisoriesWithRealCase(): void
    {
        $advisory1 = Advisory::fromArrayData([
            'reference' => 'composer://silverstripe/cms',
            'branches' => [
                '3.1.x' => [
                    'versions' => ['>=3.1.0', '<=3.1.9'],
                ],
            ],
        ]);
        $advisory2 = clone $advisory1;
        $advisory3 = Advisory::fromArrayData([
            'reference' => 'composer://silverstripe/cms',
            'branches' => [
                '3.0.x' => [
                    'versions' => ['>=3.0.0', '<=3.0.11'],
                ],
                '3.1.x' => [
                    'versions' => ['>=3.1.0', '<3.1.11'],
                ],
            ],
        ]);

        $component = new Component(PackageName::fromName('foo/bar'), $advisory1, $advisory2, $advisory3);

        self::assertSame('>=3,<=3.0.11|>=3.1,<3.1.11', $component->getConflictConstraint());
    }

    /**
     * @psalm-param non-empty-string $reference
     * @psalm-param array<non-empty-string, array{versions: non-empty-list<non-empty-string>}> $advisory1Branches
     * @psalm-param array<non-empty-string, array{versions: non-empty-list<non-empty-string>}> $advisory2Branches
     * @psalm-param non-empty-string $expected
     * @dataProvider complexRealAdvisoriesProvider
     */
    public function testSortComplexAdvisoriesWithRealCase(
        string $reference,
        array $advisory1Branches,
        array $advisory2Branches,
        string $expected
    ): void {
        $advisory1 = Advisory::fromArrayData([
            'reference' => $reference,
            'branches' => $advisory1Branches,
        ]);
        $advisory2 = clone $advisory1;
        $advisory3 = Advisory::fromArrayData([
            'reference' => $reference,
            'branches' => $advisory2Branches,
        ]);

        $component = new Component(PackageName::fromName('foo/bar'), $advisory1, $advisory2, $advisory3);

        self::assertSame($expected, $component->getConflictConstraint());
    }

    /**
     * @psalm-return non-empty-array<
     *     non-empty-string,
     *     array{
     *          non-empty-string,
     *          array<non-empty-string, array{versions: non-empty-list<non-empty-string>}>,
     *          array<non-empty-string, array{versions: non-empty-list<non-empty-string>}>,
     *          non-empty-string
     *     }
     * >
     */
    public function complexRealAdvisoriesProvider()
    {
        return [
            'Case: thelia/thelia' => [
                'composer://thelia/thelia',
                [
                    '2.1.x' => [
                        'versions' => ['>=2.1.0', '<2.1.2'],
                    ],
                ],
                [
                    '2.1.x' => [
                        'versions' => ['>=2.1.0-beta1', '<2.1.3'],
                    ],
                ],
                '>=2.1-beta.1,<2.1.3',
            ],
            'Case: magento/product-community-edition' => [
                'composer://thelia/thelia',
                // taken from CVE-2016-6485.yaml
                [
                    '2.0' => [
                        'versions' => ['>=2.0', '<2.1'],
                    ],
                    '2.1' => [
                        'versions' => ['>=2.1', '<2.2'],
                    ],
                    '2.2' => [
                        'versions' => ['>=2.2', '<2.2.6'],
                    ],
                ],
                // have to skip a lot of branches here as magento has many CVE
                // taken from CVE-2019-8159.yaml
                [
                    '2.2' => [
                        'versions' => ['>=2.2', '<2.2.10'],
                    ],
                    '2.3' => [
                        'versions' => ['>=2.3', '<2.3.2-p2'],
                    ],
                ],
                '>=2,<2.2.10|>=2.3,<2.3.2-p.2',
            ],
        ];
    }
}
