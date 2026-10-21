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

namespace RoaveTest\SecurityAdvisories\PhpVersionSources;

use Composer\Semver\Semver;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psl\Exception\InvariantViolationException;
use Psl\Json;
use Psl\Str;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Roave\SecurityAdvisories\PhpVersionSources\GetInsecurePhpVersionsFromPhpNet;

#[CoversClass(GetInsecurePhpVersionsFromPhpNet::class)]
final class GetInsecurePhpVersionsFromPhpNetTest extends TestCase
{
    public function testWillBuildConstraintFromUnsupportedAndOutdatedBranches(): void
    {
        $versions = $this->getInsecurePhpVersions(
            [
                '8' => [
                    '8.4' => ['version' => '8.4.26'],
                    '8.2' => ['version' => '8.2.34'],
                    '8.3' => ['version' => '8.3.35'],
                    '8.5' => ['version' => '8.5.11'],
                ],
            ],
            [
                '8.2' => [
                    '8.2.34' => ['tags' => ['security']],
                    '8.2.33' => ['tags' => ['security']],
                ],
                '8.3' => [
                    '8.3.35' => ['tags' => ['security']],
                    '8.3.30' => ['tags' => []],
                ],
                '8.4' => [
                    // latest release is a bugfix-only release, which is not required
                    '8.4.26' => ['tags' => ['']],
                    '8.4.25' => ['tags' => ['security']],
                    '8.4.24' => ['tags' => ['security']],
                ],
                '8.5' => [
                    '8.5.10' => ['tags' => []],
                    '8.5.9' => ['tags' => ['security']],
                    // releases of other branches must be ignored
                    '8.50.1' => ['tags' => ['security']],
                ],
            ],
        );

        self::assertSame(
            '<8.2.34|>=8.3,<8.3.35|>=8.4,<8.4.25|>=8.5,<8.5.9',
            $versions,
        );
    }

    /** @param non-empty-string $version */
    #[DataProvider('phpVersionsProvider')]
    public function testConflictsWithExpectedPhpVersions(string $version, bool $expectedToConflict): void
    {
        $constraint = $this->getInsecurePhpVersions(
            [
                '7' => ['7.4' => ['version' => '7.4.33']],
                '8' => ['8.0' => ['version' => '8.0.2']],
            ],
            [
                '7.4' => ['7.4.33' => ['tags' => ['security']]],
                '8.0' => [
                    '8.0.2' => ['tags' => []],
                    '8.0.1' => ['tags' => ['security']],
                    '8.0.0' => ['tags' => []],
                ],
            ],
        );

        self::assertSame($expectedToConflict, Semver::satisfies($version, $constraint));
    }

    /** @return non-empty-list<array{non-empty-string, bool}> */
    public static function phpVersionsProvider(): array
    {
        return [
            ['5.6.40', true],
            ['7.3.33', true],
            ['7.4.0', true],
            ['7.4.32', true],
            ['7.4.33', false],
            ['8.0.0', true],
            ['8.0.1', false],
            ['8.0.2', false],
            ['8.1.0', false],
            ['9.0.0', false],
        ];
    }

    public function testWillSkipBranchesWithoutSecurityReleases(): void
    {
        self::assertSame(
            '<8.4|>=8.5,<8.5.1',
            $this->getInsecurePhpVersions(
                ['8' => ['8.4' => [], '8.5' => [], '8.6' => []]],
                [
                    '8.4' => ['8.4.1' => ['tags' => []]],
                    '8.5' => ['8.5.1' => ['tags' => ['security']]],
                    // an initial release flagged as security release has no older versions to exclude
                    '8.6' => ['8.6.0' => ['tags' => ['security']]],
                ],
            ),
        );
    }

    public function testWillIgnoreInvalidBranchNames(): void
    {
        self::assertSame(
            '<8.4',
            $this->getInsecurePhpVersions(
                ['8' => ['8.4' => [], 'foo' => [], '8' => [], '8.4.1' => []]],
                ['8.4' => []],
            ),
        );
    }

    public function testWillFailIfNoSupportedBranchesAreFound(): void
    {
        $this->expectException(InvariantViolationException::class);

        $this->getInsecurePhpVersions(['8' => ['foo' => []]], []);
    }

    /**
     * @param array<array-key, array<array-key, array<string, mixed>>> $activeBranches
     * @param array<string, array<string, array{tags: list<string>}>>  $branchReleases
     */
    private function getInsecurePhpVersions(array $activeBranches, array $branchReleases): string
    {
        $client = $this->createStub(ClientInterface::class);

        $client->method('sendRequest')
            ->willReturnCallback(static function (RequestInterface $request) use (
                $activeBranches,
                $branchReleases,
            ): Response {
                $uri = $request->getUri();

                self::assertSame('GET', $request->getMethod());
                self::assertSame('https', $uri->getScheme());
                self::assertSame('www.php.net', $uri->getHost());

                if ($uri->getPath() === '/releases/active.php') {
                    return new Response(200, [], Json\encode($activeBranches));
                }

                self::assertSame('/releases/index.php', $uri->getPath());
                self::assertMatchesRegularExpression('/^json&max=-1&version=\d+\.\d+$/', $uri->getQuery());

                $branch = Str\after($uri->getQuery(), 'version=') ?? '';

                return new Response(200, [], Json\encode((object) ($branchReleases[$branch] ?? [])));
            });

        return (new GetInsecurePhpVersionsFromPhpNet($client))()->getConstraintString();
    }
}
