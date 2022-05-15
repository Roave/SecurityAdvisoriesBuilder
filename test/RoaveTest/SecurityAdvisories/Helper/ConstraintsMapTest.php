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

namespace RoaveTest\SecurityAdvisories\Helper;

use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\Helper\ConstraintsMap;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Helper\ConstraintsMap}
 *
 * @covers \Roave\SecurityAdvisories\Helper\ConstraintsMap
 */
final class ConstraintsMapTest extends TestCase
{
    /**
     * @param array<string, array<string, array<string, string>>> $data
     * @param array<Advisory>                                     $incomingAdvisories
     *
     * @dataProvider newAdvisoriesDataProvider
     */
    public function testAdvisoriesDiffDetectsUpdatedAndNewAdvisory(
        array $data,
        array $incomingAdvisories,
        string $expectedAdvisoryConstraint
    ): void {
        $map    = ConstraintsMap::fromArray($data['conflict']);
        $result = $map->advisoriesDiff($incomingAdvisories);

        self::assertCount(1, $result);
        self::assertEquals($expectedAdvisoryConstraint, $result[0]->getConstraint());
    }

    /**
     * @param array<string, array<string, array<string, string>>> $data
     * @param array<Advisory>                                     $incomingAdvisories
     *
     * @dataProvider sameAdvisoriesDataProvider
     */
    public function testAdvisoriesDiffDetectsNonUpdatedAdvisory(
        array $data,
        array $incomingAdvisories,
    ): void {
        $map    = ConstraintsMap::fromArray($data['conflict']);
        $result = $map->advisoriesDiff($incomingAdvisories);

        self::assertCount(0, $result);
    }

    /**
     * @return array<string, mixed>
     */
    public function sameAdvisoriesDataProvider(): array
    {
        return [
            'single range equals to already existing range' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            ['versions' => ['>=4,<4.4.56']],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>=4,<4.4.56',
            ],
            'all ranges are fully included' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            ['versions' => ['>=4,<4.4.56']],
                            ['versions' => ['>=4.5,<4.9.18']],
                            ['versions' => ['>=4.10,<4.11.7']],
                            ['versions' => ['>=4.13,<4.13.3']],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>=4,<4.4.56',
            ],
            'smaller single range fully included' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            ['versions' => ['>4.1,<4.2']],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>=4,<4.4.56',
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function newAdvisoriesDataProvider(): array
    {
        return [
            'existing package but with new version added' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            ['versions' => ['>5']],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>5',
            ],
            'new package ' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            ['versions' => ['>1']],
                        ],
                        'reference' => 'composer://test/example',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>1',
            ],
            'advisory with expanded range' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            [
                                'versions' =>
                                    ['>=4.13', '<4.13.4'], // just a bit over the edge
                            ],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>=4.13,<4.13.4',
            ],
            'existing conflict updated with new range' => [
                [
                    'conflict' => ['foo/bar' => '>=4,<4.4.56|>=4.5,<4.9.18|>=4.10,<4.11.7|>=4.13,<4.13.3'],
                ],
                [
                    Advisory::fromArrayData([
                        'branches' => [
                            [
                                'versions' =>
                                    ['>=4.13', '<4.13.3'],
                            ],
                            [
                                'versions' =>
                                    ['>6'],
                            ],
                        ],
                        'reference' => 'composer://foo/bar',
                        'source' => ['summary' => 'summary', 'link' => 'link'],
                    ]),
                ],
                '>=4.13,<4.13.3|>6',
            ],
        ];
    }
}
