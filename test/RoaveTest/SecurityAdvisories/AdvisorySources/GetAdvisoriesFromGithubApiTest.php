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
use InvalidArgumentException;
use Nyholm\Psr7\Response;
use PHPStan\Testing\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;
use Safe\Exceptions\JsonException;
use Safe\Exceptions\StringsException;
use function array_map;
use function sprintf;

class GetAdvisoriesFromGithubApiTest extends TestCase
{
    /**
     * @param ResponseInterface[] $apiResponses
     *
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws StringsException
     *
     * @dataProvider correctResponsesSequenceDataProvider
     */
    public function testGithubAdvisoriesIsAbleToProduceAdvisories(array $apiResponses) : void
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
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws StringsException
     *
     * @dataProvider responsesWithIncorrectRangesProvider
     */
    public function testGithubAdvisoriesFailToCompileGettingIncorrectRanges(ResponseInterface $response) : void
    {
        $client = $this->createMock(Client::class);

        $client->expects($this->once())
            ->method('sendRequest')
            ->willReturn($response);

        $this->expectException(InvalidArgumentException::class);

        (new GetAdvisoriesFromGithubApi($client, 'some_token'))()->next();
    }

    /**
     * @return ResponseInterface[]
     */
    public function correctResponsesSequenceDataProvider() : array
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
                        "hasNextPage": true,
                        "endCursor": "Y3Vyc29yOnYyOpK5MjAyMC0wMS0wOFQxOToxNTowNiswMjowMM0LdA=="
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

        return [
            [
                [
                    $first,
                    $second,
                ],
            ],
        ];
    }

    /**
     * @return ResponseInterface[][]
     */
    public function responsesWithIncorrectRangesProvider() : array
    {
        $query = <<<'QUERY'
                {
                  "data": {
                    "securityVulnerabilities": {
                      "edges": [
                        {
                          "cursor": "Y3Vyc29yOnYyOpK5MjAyMC0wMS0wOFQxOToxNTowNiswMjowMM0LdA==",
                          "node": {
                            "vulnerableVersionRange": "%s",
                            "package": {
                              "name": "enshrined/svg-sanitize"
                            }
                          }
                        }
                      ],
                      "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": "Y3Vyc29yOnYyOpK5MjAyMC0wMS0wOFQxOToxNTowNiswMjowMM0LdA=="
                      }
                    }
                  }
                }
            QUERY;

        $incorrectRanges = [
            '',
            ',',
            '> 1,', // correct open constraint, but empty closing constraint
            'a,b,c', // we may have a max of 2 versions
        ];

        return [
            array_map(
                static function ($range) use ($query) {
                    return new Response(200, [], sprintf($query, $range));
                },
                $incorrectRanges
            ),
        ];
    }
}
