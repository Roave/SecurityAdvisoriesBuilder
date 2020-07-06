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

namespace RoaveTest\SecurityAdvisories\AdvisorySources;

use Generator;
use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisories;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromMultipleSources;
use function iterator_to_array;

class GetAdvisoriesFromMultipleSourcesTest extends TestCase
{
    public function testMultipleAdvisoriesSources() : void
    {
        $someAdvisories = $this->createMock(GetAdvisories::class);

        $someAdvisories->expects(self::once())
            ->method('__invoke')
            ->willReturn($this->getGenerator());

        $advisories = new GetAdvisoriesFromMultipleSources($someAdvisories);

        self::assertEquals(
            [
                Advisory::fromArrayData([
                    'reference' => 'test_package',
                    'branches' => [['versions' => ['<1']]],
                ]),
            ],
            iterator_to_array($advisories())
        );
    }

    private function getGenerator() : Generator
    {
        return yield Advisory::fromArrayData([
            'reference' => 'test_package',
            'branches' => [['versions' => ['<1']]],
        ]);
    }
}
