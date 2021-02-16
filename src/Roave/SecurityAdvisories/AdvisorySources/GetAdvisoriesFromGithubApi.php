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
use InvalidArgumentException;
use Nyholm\Psr7\Request;
use Psl\Type\Exception\AssertException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\Exception\InvalidPackageName;
use Safe\Exceptions\JsonException;
use Safe\Exceptions\StringsException;

use function count;
use function explode;
use function Psl\Type\int;
use function Psl\Type\iterable;
use function Psl\Type\non_empty_string;
use function Safe\json_decode;
use function Safe\json_encode;
use function Safe\sprintf;

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

    /** @psalm-param non-empty-string $token */
    public function __construct(
        ClientInterface $client,
        string $token
    ) {
        $this->client = $client;
        $this->token  = $token;
    }

    /**
     * @return Generator<Advisory>
     *
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws StringsException
     */
    public function __invoke(): Generator
    {
        foreach ($this->getAdvisories() as $item) {
            $versions = explode(',', $item['node']['vulnerableVersionRange']);

            try {
                iterable(
                    int(),
                    non_empty_string()
                )->assert($versions);
            } catch (AssertException $failure) {
                throw new InvalidArgumentException($failure->getMessage(), (int) $failure->getCode(), $failure);
            }

            if (count($versions) > 2) {
                throw new InvalidArgumentException('More than 2 version range delimiters found');
            }

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
     *
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws StringsException
     *
     * @psalm-return iterable<int, array{
     *      cursor: string,
     *      node: array{
     *          vulnerableVersionRange: string,
     *          package: array{name: string}
     *      }
     * }>
     */
    private function getAdvisories(): iterable
    {
        $cursor = '';

        do {
            $response = $this->client->sendRequest($this->getRequest($cursor));
            /** @psalm-var array{
             * data: array{securityVulnerabilities: array{
             *   edges: array<int, array{
             *     cursor: string,
             *     node: array{vulnerableVersionRange: string, package: array{name: string}}}>,
             *   pageInfo: array{hasNextPage: bool, endCursor: string}
             * }}} $data
             */
            $data            = json_decode($response->getBody()->__toString(), true);
            $vulnerabilities = $data['data']['securityVulnerabilities'];

            yield from $vulnerabilities['edges'];

            $hasNextPage = $vulnerabilities['pageInfo']['hasNextPage'];
            $cursor      = $vulnerabilities['pageInfo']['endCursor'];
        } while ($hasNextPage);
    }

    /**
     * @throws JsonException
     * @throws StringsException
     */
    private function getRequest(string $cursor): RequestInterface
    {
        return new Request(
            'POST',
            'https://api.github.com/graphql',
            [
                'Authorization' => sprintf('bearer %s', $this->token),
                'Content-Type' => 'application/json',
                'User-Agent' => 'Curl',
            ],
            $this->queryWithCursor($cursor)
        );
    }

    /**
     * @throws JsonException
     * @throws StringsException
     */
    private function queryWithCursor(string $cursor): string
    {
        $after = $cursor === '' ? '' : sprintf(', after: "%s"', $cursor);

        return json_encode(['query' => sprintf(self::GRAPHQL_QUERY, $after)]);
    }
}
