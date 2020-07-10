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

use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromFriendsOfPhp;
use function iterator_to_array;

class GetAdvisoriesFromFriendsOfPhpTest extends TestCase
{
    public function testThatAdvisoriesAreBuiltFromYamlFiles() : void
    {
        $advisories = (new GetAdvisoriesFromFriendsOfPhp(
            __DIR__ . '/security-advisories'
        ))();

        self::assertEquals(
            [
                Advisory::fromArrayData([
                    'branches'  => [
                        '1.x' => [
                            'time'     => '2017-05-15 09:09:00',
                            'versions' => ['<1.2'],
                        ],
                    ],
                    'reference' => 'composer://3f/pygmentize',
                ]),
            ],
            iterator_to_array($advisories, false)
        );
    }
}
