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

namespace Roave\SecurityAdvisories\AdvisorySources;

use Generator;
use Nyholm\Psr7\Request;
use Psl;
use Psl\Json;
use Psl\Str;
use Psl\Type;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\Exception\InvalidPackageName;

final class GetAdvisoriesFromGithubApi implements GetAdvisories
{
    private const GRAPHQL_QUERY = 'query {
            securityVulnerabilities(ecosystem: COMPOSER, first: 100 %s) {
                edges {
                    cursor
                    node {
                        vulnerableVersionRange
                        package {
                            name
                        }
                    }
                }
                pageInfo {
                      hasNextPage
                      endCursor
                }
            }
        }';

    private ClientInterface $client;

    private string $token;

    public function __construct(
        ClientInterface $client,
        string $token
    ) {
        Psl\invariant(! Str\is_empty($token), 'Unable to proceed. Please make sure you have GITHUB_TOKEN environment variable set up.');

        $this->client = $client;
        $this->token  = $token;
    }

    /**
     * @return Generator<Advisory>
     *
     * @throws ClientExceptionInterface
     */
    public function __invoke(): Generator
    {
        foreach ($this->getAdvisories() as $item) {
            $versions = Type\shape([0 => Type\non_empty_string(), 1 => Type\optional(Type\non_empty_string())])
                ->assert(Str\split($item['node']['vulnerableVersionRange'], ','));

            try {
                yield Advisory::fromArrayData(
                    [
                        'reference' => $item['node']['package']['name'],
                        'branches'  => [['versions' => $versions]],
                    ]
                );
            } catch (InvalidPackageName) {
                // Sometimes, github advisories publish CVEs with malformed package names, and that
                // should not crash our entire pipeline.
                // @TODO add logging here?
                continue;
            }
        }
    }

    /**
     * GitHub response will always contain 'pageInfo' element
     * that is used to do a sequence of "paged" requests.
     * Note: 'endCursor' contains the least cursor in the given batch
     *
     * @return string[]
     * @psalm-return iterable<int, array{
     *      cursor: string,
     *      node: array{
     *          vulnerableVersionRange: string,
     *          package: array{name: string}
     *      }
     * }>
     *
     * @throws ClientExceptionInterface
     */
    private function getAdvisories(): iterable
    {
        $cursor = '';

        do {
            $response        = $this->client->sendRequest($this->getRequest($cursor));
            $data            = Json\typed($response->getBody()->__toString(), Type\shape([
                'data' => Type\shape([
                    'securityVulnerabilities' => Type\shape([
                        'edges' => Type\dict(Type\int(), Type\shape([
                            'cursor' => Type\string(),
                            'node' => Type\shape([
                                'vulnerableVersionRange' => Type\string(),
                                'package' => Type\shape(['name' => Type\string()]),
                            ]),
                        ])),
                        'pageInfo' => Type\shape([
                            'hasNextPage' => Type\bool(),
                            'endCursor' => Type\nullable(Type\string()),
                        ]),
                    ]),
                ]),
            ]));
            $vulnerabilities = $data['data']['securityVulnerabilities'];

            yield from $vulnerabilities['edges'];

            $hasNextPage = $vulnerabilities['pageInfo']['hasNextPage'];
            $cursor      = $vulnerabilities['pageInfo']['endCursor'];
        } while ($hasNextPage && $cursor !== null);
    }

    private function getRequest(string $cursor): RequestInterface
    {
        return new Request(
            'POST',
            'https://api.github.com/graphql',
            [
                'Authorization' => Str\format('bearer %s', $this->token),
                'Content-Type' => 'application/json',
                'User-Agent' => 'Curl',
            ],
            $this->queryWithCursor($cursor)
        );
    }

    private function queryWithCursor(string $cursor): string
    {
        $after = $cursor === '' ? '' : Str\format(', after: "%s"', $cursor);

        return Json\encode(['query' => Str\format(self::GRAPHQL_QUERY, $after)]);
    }
}
