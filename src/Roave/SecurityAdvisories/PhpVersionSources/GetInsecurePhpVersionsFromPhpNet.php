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

namespace Roave\SecurityAdvisories\PhpVersionSources;

use Composer\Semver\Semver;
use Nyholm\Psr7\Request;
use Psl;
use Psl\Dict;
use Psl\Json;
use Psl\Regex;
use Psl\Str;
use Psl\Type;
use Psl\Vec;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Roave\SecurityAdvisories\VersionConstraint;

use function in_array;

/**
 * Builds a constraint matching all PHP versions that should not be used:
 *
 *  - all PHP versions belonging to branches that no longer receive security support
 *  - all PHP versions belonging to supported branches, for which a newer security release is available
 */
final class GetInsecurePhpVersionsFromPhpNet
{
    private const string ACTIVE_BRANCHES_URL = 'https://www.php.net/releases/active.php';
    private const string BRANCH_RELEASES_URL = 'https://www.php.net/releases/index.php?json&max=-1&version=%s';

    public function __construct(private readonly ClientInterface $client)
    {
    }

    /** @throws ClientExceptionInterface */
    public function __invoke(): VersionConstraint
    {
        $supportedBranches = $this->getSupportedBranches();

        // everything below the oldest supported branch no longer receives security fixes
        $constraints = ['<' . $supportedBranches[0]];

        foreach ($supportedBranches as $branch) {
            $latestSecurityRelease = $this->getLatestSecurityRelease($branch);

            if ($latestSecurityRelease === null || $latestSecurityRelease === $branch . '.0') {
                continue;
            }

            $constraints[] = Str\format('>=%s,<%s', $branch, $latestSecurityRelease);
        }

        return VersionConstraint::fromString(Str\join($constraints, '|'));
    }

    /**
     * Retrieves all branches that still receive (at least) security support, sorted from oldest to newest
     *
     * @return non-empty-list<non-empty-string>
     *
     * @throws ClientExceptionInterface
     */
    private function getSupportedBranches(): array
    {
        $branchesByMajor = Json\typed(
            $this->get(self::ACTIVE_BRANCHES_URL),
            Type\dict(Type\array_key(), Type\dict(Type\non_empty_string(), Type\mixed())),
        );

        $branches = Vec\filter(
            Vec\flat_map($branchesByMajor, static fn (array $branches): array => Vec\keys($branches)),
            static fn (string $branch): bool => Regex\matches($branch, '/^\d+\.\d+$/'),
        );

        Psl\invariant($branches !== [], 'Unable to find any supported PHP branch on php.net.');

        return Type\non_empty_vec(Type\non_empty_string())
            ->assert(Semver::sort($branches));
    }

    /**
     * @param non-empty-string $branch
     *
     * @return non-empty-string|null
     *
     * @throws ClientExceptionInterface
     */
    private function getLatestSecurityRelease(string $branch): string|null
    {
        $releases = Json\typed(
            $this->get(Str\format(self::BRANCH_RELEASES_URL, $branch)),
            Type\dict(Type\non_empty_string(), Type\shape(['tags' => Type\vec(Type\string())], true)),
        );

        $securityReleases = Vec\keys(Dict\filter_with_key(
            $releases,
            static fn (string $version, array $release): bool => Str\starts_with($version, $branch . '.')
                && in_array('security', $release['tags'], true),
        ));

        return Type\nullable(Type\non_empty_string())
            ->assert(Semver::rsort($securityReleases)[0] ?? null);
    }

    /** @throws ClientExceptionInterface */
    private function get(string $url): string
    {
        return $this->client
            ->sendRequest(new Request('GET', $url, ['User-Agent' => 'Roave/SecurityAdvisoriesBuilder']))
            ->getBody()
            ->__toString();
    }
}
