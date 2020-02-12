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
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Roave\SecurityAdvisories\Advisory;
use Safe\Exceptions\JsonException;
use Safe\Exceptions\StringsException;
use Webmozart\Assert\Assert;
use function array_map;
use function array_merge;
use function count;
use function explode;
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

    public function __construct(
        ClientInterface $client,
        string $token
    ) {
        Assert::stringNotEmpty($token);

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
    public function __invoke() : Generator
    {
        return yield from array_map(
            static function (array $item) {
                $versions = explode(',', $item['node']['vulnerableVersionRange']);
                Assert::lessThanEq(count($versions), 2);
                Assert::allStringNotEmpty($versions);

                return Advisory::fromArrayData(
                    [
                        'reference' => $item['node']['package']['name'],
                        'branches' => [['versions' => $versions]],
                    ]
                );
            },
            $this->getAdvisories()
        );
    }

    /**
     * GitHub response will always contain 'pageInfo' element
     * that is used to do a sequence of "paged" requests.
     * Note: 'endCursor' contains the least cursor in the given batch
     *
     * @return Advisory[]
     *
     * @throws ClientExceptionInterface
     * @throws JsonException
     * @throws StringsException
     */
    private function getAdvisories() : array
    {
        $advisories = [];
        $cursor     = '';

        do {
            $response        = $this->client->sendRequest($this->getRequest($cursor));
            $data            = json_decode($response->getBody()->__toString(), true);
            $vulnerabilities = $data['data']['securityVulnerabilities'];
            $advisories      = array_merge($advisories, $vulnerabilities['edges']);
            $hasNextPage     = $vulnerabilities['pageInfo']['hasNextPage'];
            $cursor          = $vulnerabilities['pageInfo']['endCursor'];
        } while ($hasNextPage);

        return $advisories;
    }

    /**
     * @throws JsonException
     * @throws StringsException
     */
    private function getRequest(string $cursor) : RequestInterface
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
    private function queryWithCursor(string $cursor) : string
    {
        $after = $cursor === '' ? '' : sprintf(', after: "%s"', $cursor);

        return json_encode(['query' => sprintf(self::GRAPHQL_QUERY, $after)]);
    }
}
