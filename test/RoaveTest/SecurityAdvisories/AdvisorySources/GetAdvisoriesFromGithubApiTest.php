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

use Http\Client\Curl\Client;
use Nyholm\Psr7\Response;
use PHPStan\Testing\TestCase;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;

class GetAdvisoriesFromGithubApiTest extends TestCase
{
    /**
     * fixme: should we test private methods ? people on internet say NO
     *
     * @dataProvider testProvider
     */
    public function testRequest($apiResponses) : void
    {
        $client = $this->createMock(Client::class);

        $client->expects($this->exactly(2))
            ->method('sendRequest')
            ->willReturnOnConsecutiveCalls(...$apiResponses);

        $advisories = new GetAdvisoriesFromGithubApi($client, 'some_token');

        foreach ($advisories() as $item) {
            $this->assertInstanceOf(Advisory::class, $item);
        }
    }

    /**
     * There is an "discussion" about Stream body pointer placement
     * @see https://github.com/Nyholm/psr7/issues/99
     *
     * @return array
     */
    public function responsesDataProvider() : array
    {
        $responseBodies = [
            <<<'F'
                {
                  "data": {
                    "securityVulnerabilities": {
                      "edges": [
                        {
                          "cursor": "Y3Vyc29yOnYyOpK5MjAyMC0wMS0wOFQxOToxNTowNiswMjowMM0LdA==",
                          "node": {
                            "vulnerableVersionRange": "< 0.12.0",
                            "package": {
                              "name": "enshrined/svg-sanitize"
                            }
                          }
                        }
                      ],
                      "pageInfo": {
                        "hasNextPage": true
                      }
                    }
                  }
                }
            F,
            <<<'S'
                {
                  "data": {
                    "securityVulnerabilities": {
                      "edges": [],
                      "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                      }
                    }
                  }
                }
            S,
        ];

        $first  = new Response(200, [], $responseBodies[0]);
        $second = new Response(200, [], $responseBodies[1]);

        $first->getBody()->rewind();
        $second->getBody()->rewind();

        return [
            [
                [
                    $first,
                    $second,
                ],
            ],
        ];
    }
}
