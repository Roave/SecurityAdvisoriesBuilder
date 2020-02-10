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
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Message\ResponseInterface;
use ReflectionException;
use ReflectionMethod;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;
use Safe\Exceptions\JsonException;
use Safe\Exceptions\StringsException;
use function iterator_to_array;
use function Safe\json_decode;
use function Safe\sprintf;

class GetAdvisoriesFromGithubApiTest extends TestCase
{
    public function testGithubAdvisoriesHasToken() : void
    {
        $client = $this->createMock(Client::class);

        $this->expectException(InvalidArgumentException::class);

        new GetAdvisoriesFromGithubApi($client, '');
    }

    /**
     * @throws ReflectionException
     *
     * @dataProvider cursorProvider
     */
    public function testGithubAdvisoriesQueryMethod(string $cursor, bool $shouldContainCursor) : void
    {
        $client = $this->createMock(Client::class);

        $githubAdvisories = new GetAdvisoriesFromGithubApi($client, 'token');

        $overlapsWithReflection = new ReflectionMethod($githubAdvisories, 'queryWithCursor');

        $overlapsWithReflection->setAccessible(true);

        $jsonEncodedQuery = $overlapsWithReflection->invoke($githubAdvisories, $cursor);

        $decodedQuery = json_decode($jsonEncodedQuery, true);

        self::assertArrayHasKey('query', $decodedQuery);

        if ($shouldContainCursor) {
            self::assertStringContainsString(sprintf('after: "%s"', $cursor), $decodedQuery['query']);
        } else {
            self::assertStringNotContainsString('after: ""', $decodedQuery['query']);
        }
    }

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

        $client->expects(self::exactly(2))
            ->method('sendRequest')
            ->willReturnOnConsecutiveCalls(...$apiResponses);

        $advisories = new GetAdvisoriesFromGithubApi($client, 'some_token');

        self::assertEquals(
            [
                Advisory::fromArrayData([
                    'reference' => 'enshrined/svg-sanitize',
                    'branches'  => [['versions' => ['> 0.12.0, < 0.12.1 ']]],
                ]),
                Advisory::fromArrayData([
                    'reference' => 'foo/bar',
                    'branches'  => [['versions' => ['> 1.2.3, < 4.5.6 ']]],
                ]),
            ],
            iterator_to_array($advisories(), false)
        );
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

        $client->expects(self::once())
            ->method('sendRequest')
            ->willReturn($response);

        self::expectException(InvalidArgumentException::class);

        (new GetAdvisoriesFromGithubApi($client, 'some_token'))()->next();
    }

    /**
     * @return mixed[]
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
                            "vulnerableVersionRange": "> 0.12.0, < 0.12.1 ",
                            "package": {
                              "name": "enshrined/svg-sanitize"
                            }
                          }
                        },
                        {
                          "cursor": "Y3Vyc29yOnYyOpK5MjAyMC0wMS0wOFQxOToxNTowNiswMjowMM0LdB==",
                          "node": {
                            "vulnerableVersionRange": "> 1.2.3, < 4.5.6 ",
                            "package": {
                              "name": "foo/bar"
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
     * @return mixed[]
     *
     * @throws StringsException
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

        $responses = [];

        foreach ($incorrectRanges as $range) {
            $responses[] = [new Response(200, [], sprintf($query, $range))];
        }

        return $responses;
    }

    /**
     * @return mixed[]
     */
    public function cursorProvider() : array
    {
        return [
            [
                '',
                false,
            ],
            [
                'abc',
                true,
            ],
        ];
    }
}
