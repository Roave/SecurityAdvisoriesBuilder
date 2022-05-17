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

namespace Roave\SecurityAdvisories;

use DateTime;
use DateTimeZone;
use ErrorException;
use Http\Client\Curl\Client;
use Psl\Dict;
use Psl\Env;
use Psl\Filesystem;
use Psl\Json;
use Psl\Shell;
use Psl\Str;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesAdvisoryRuleDecorator;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromFriendsOfPhp;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromMultipleSources;
use Roave\SecurityAdvisories\Helper\ConstraintsMap;
use Roave\SecurityAdvisories\Rule\RuleProviderFactory;

use function file_get_contents;
use function iterator_to_array;
use function set_error_handler;

use const E_NOTICE;
use const E_STRICT;
use const E_WARNING;
use const PHP_BINARY;

(static function (): void {
    require_once __DIR__ . '/vendor/autoload.php';

    set_error_handler(
        static function (int $errorCode, string $message = '', string $file = '', int $line = 0): bool {
            throw new ErrorException($message, 0, $errorCode, $file, $line);
        },
        E_STRICT | E_NOTICE | E_WARNING
    );

    $token                     = Env\get_var('GITHUB_TOKEN') ?? '';
    $authentication            = $token === '' ? '' : $token . ':x-oauth-basic@';
    $advisoriesRepository      = 'https://' . $authentication . 'github.com/FriendsOfPHP/security-advisories.git';
    $roaveAdvisoriesRepository = 'https://' . $authentication . 'github.com/Roave/SecurityAdvisories.git';
    $buildDir                  = __DIR__ . '/build';
    $baseComposerJson          = [
        'name'          => 'roave/security-advisories',
        'type'          => 'metapackage',
        'description'   => 'Prevents installation of composer packages with known security vulnerabilities: '
            . 'no API, simply require it',
        'license'       => 'MIT',
        'authors'       => [
            [
                'name'  => 'Marco Pivetta',
                'role'  => 'maintainer',
                'email' => 'ocramius@gmail.com',
            ],
            [
                'name'  => 'Ilya Tribusean',
                'role'  => 'maintainer',
                'email' => 'slash3b@gmail.com',
            ],
        ],
    ];

    $cleanBuildDir = static function () use ($buildDir): void {
        Shell\execute('rm', ['-rf', $buildDir]);
        Shell\execute('mkdir', [$buildDir]);
    };

    $cloneAdvisories = static function () use ($advisoriesRepository, $buildDir): void {
        Shell\execute('git', ['clone', $advisoriesRepository, $buildDir . '/security-advisories']);
    };

    $cloneRoaveAdvisories = static function () use ($roaveAdvisoriesRepository, $buildDir): void {
        Shell\execute('git', ['clone', $roaveAdvisoriesRepository, $buildDir . '/roave-security-advisories']);
    };

    $buildComponents =
        /**
         * @param iterable<Advisory> $advisories
         *
         * @return Component[]
         */
        static function (iterable $advisories): array {
            $indexedAdvisories = [];
            $components        = [];

            foreach ($advisories as $advisory) {
                $indexedAdvisories[$advisory->package->packageName][] = $advisory;
            }

            foreach ($indexedAdvisories as $componentName => $componentAdvisories) {
                $components[$componentName] = new Component($componentAdvisories[0]->package, ...$componentAdvisories);
            }

            return $components;
        };

    $buildConflicts =
        /**
         * @param Component[] $components
         *
         * @return array<non-empty-string, non-empty-string>
         */
        static function (array $components): array {
            $conflicts = [];

            foreach ($components as $component) {
                $constraint = $component->getConflictConstraint();
                if ($constraint === '') {
                    continue;
                }

                $conflicts[$component->name->packageName] = $constraint;
            }

            return Dict\sort_by_key($conflicts);
        };

    $buildConflictsJson = static function (array $baseConfig, array $conflicts): string {
        return Json\encode(Dict\merge($baseConfig, ['conflict' => $conflicts]), true);
    };

    $writeJson = static function (string $jsonString, string $path): void {
        Filesystem\write_file($path, $jsonString . "\n");
    };

    $validateComposerJson = static function (string $composerJsonPath): void {
        Shell\execute(
            PHP_BINARY,
            [__DIR__ . '/vendor/bin/composer', 'validate'],
            Filesystem\get_directory($composerJsonPath)
        );
    };

    $copyGeneratedComposerJson = static function (
        string $sourceComposerJsonPath,
        string $targetComposerJsonPath
    ): void {
        Shell\execute('cp', [$sourceComposerJsonPath, $targetComposerJsonPath]);
    };

    $commitComposerJson = static function (string $composerJsonPath, array $addedAdvisories): void {
        $originalHash = Shell\execute(
            'git',
            ['rev-parse', 'HEAD'],
            Filesystem\get_directory($composerJsonPath) . '/../security-advisories'
        );
        $originalHash = Str\trim($originalHash);

        $workingDirectory = Filesystem\get_directory($composerJsonPath);
        Shell\execute('git', ['add', (string) Filesystem\canonicalize($composerJsonPath)], $workingDirectory);

        $message = Str\format(
            'Committing generated "composer.json" file as per "%s"',
            (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::W3C)
        );

        $message .= "\n" . Str\format(
            'Original commit: "%s"',
            'https://github.com/FriendsOfPHP/security-advisories/commit/' . $originalHash,
        );

        $updatedAdvisoriesMessage = '';
        foreach ($addedAdvisories as $advisory) {
            $updatedAdvisoriesMessage .= Str\format(
                "\n\t%-15s| %s\n\t%-15s| %s\n\t%-15s| %s\n\t%-15s| %s\n",
                'Package name',
                $advisory->package->packageName,
                'Summary',
                $advisory->source->summary,
                'URI',
                $advisory->source->uri,
                'Constraints',
                $advisory->getConstraint() ?? '',
            );
        }

        if (Str\Grapheme\length($updatedAdvisoriesMessage) !== 0) {
            $updatedAdvisoriesMessage = "\n\n Security advisories updated:" . $updatedAdvisoriesMessage;
            $message                 .= $updatedAdvisoriesMessage . "\n";
        }

        try {
            Shell\execute('git', ['diff-index', '--quiet', 'HEAD'], $workingDirectory);
        } catch (Shell\Exception\FailedExecutionException) {
            Shell\execute('git', ['commit', '-m', $message], $workingDirectory);
        }
    };

    // cleanup:
    $cleanBuildDir();
    $cloneAdvisories();
    $cloneRoaveAdvisories();

    $getAdvisories = new GetAdvisoriesAdvisoryRuleDecorator(
        (new GetAdvisoriesFromMultipleSources(
            (new GetAdvisoriesFromFriendsOfPhp($buildDir . '/security-advisories')),
            (new GetAdvisoriesFromGithubApi(
                new Client(),
                $token,
            )),
        )),
        (new RuleProviderFactory())(),
    );

    // actual work:
    $writeJson(
        $buildConflictsJson(
            $baseComposerJson,
            $buildConflicts(
                $buildComponents(
                    $getAdvisories()
                )
            )
        ),
        __DIR__ . '/build/composer.json'
    );

    $validateComposerJson(__DIR__ . '/build/composer.json');

    $prevComposerJSONFileData = file_get_contents(__DIR__ . '/build/roave-security-advisories/composer.json');
    /** @var array<string,  array<string, string>> $prevComposerDecodedData */
    $prevComposerDecodedData = Json\decode($prevComposerJSONFileData, true);
    $currentConstraints      = ConstraintsMap::fromArray($prevComposerDecodedData['conflict']);
    $updatedAdvisories       = $currentConstraints->advisoriesDiff(iterator_to_array($getAdvisories()));

    $copyGeneratedComposerJson(
        __DIR__ . '/build/composer.json',
        __DIR__ . '/build/roave-security-advisories/composer.json'
    );

    $commitComposerJson(__DIR__ . '/build/roave-security-advisories/composer.json', $updatedAdvisories);
})();
