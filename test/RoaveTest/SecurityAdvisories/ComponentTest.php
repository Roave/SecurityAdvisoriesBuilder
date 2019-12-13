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

/**
 * Tests for {@see \Roave\SecurityAdvisories\Component}
 *
 * @covers \Roave\SecurityAdvisories\Component
 */
final class ComponentTest extends TestCase
{
    public function testFromMultipleAdvisories() : void
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

        $component = new Component('foo/bar', $advisory1, $advisory2);

        $expected = '>=1-beta.1.1,<1.1-beta.1.1|>=2-beta.1.1,<2.1-beta.1.1|' .
            '>=3-beta.1.1,<3.1-beta.1.1|>=4-beta.1.1,<4.1-beta.1.1';
        self::assertSame($expected, $component->getConflictConstraint());
        self::assertSame('foo/bar', $component->getName());
    }

    public function testDeDuplicatesOverlappingAdvisories() : void
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

        $component = new Component('foo/bar', $advisory1, $advisory2, $advisory3);

        self::assertSame('>=1,<1.1|>=2,<2.1|>=3,<3.1', $component->getConflictConstraint());
        self::assertSame('foo/bar', $component->getName());
    }

    public function testDeDuplicatesOverlappingComplexAdvisories() : void
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

        $component = new Component('foo/bar', $advisory1, $advisory2, $advisory3);

        self::assertSame('>=1-p.1.1.2,<1.1-b.1.1.3|>=2-rc,<2.1-p|>=3-stable.5,<3.1', $component->getConflictConstraint());
        self::assertSame('foo/bar', $component->getName());
    }

    public function testSortAdvisoriesWithRealCase() : void
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

        $component = new Component('foo/bar', $advisory1, $advisory2, $advisory3);

        self::assertSame('>=3,<=3.0.11|>=3.1,<3.1.11', $component->getConflictConstraint());
    }

    public function testSortComplexAdvisoriesWithRealCase() : void
    {
        $advisory1 = Advisory::fromArrayData([
            'reference' => 'composer://thelia/thelia',
            'branches' => [
                '2.1.x' => [
                    'versions' => ['>=2.1.0', '<2.1.2'],
                ],
            ],
        ]);
        $advisory2 = clone $advisory1;
        $advisory3 = Advisory::fromArrayData([
            'reference' => 'composer://thelia/thelia',
            'branches' => [
                '2.1.x' => [
                    'versions' => ['>=2.1.0-beta1', '<2.1.3'],
                ],
            ],
        ]);

        $component = new Component('foo/bar', $advisory1, $advisory2, $advisory3);

        self::assertSame('>=2.1-beta.1,<2.1.3', $component->getConflictConstraint());
    }
}
