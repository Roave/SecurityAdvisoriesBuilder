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
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromFriendsOfPhp;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromMultipleSources;
use UnexpectedValueException;

use function array_filter;
use function array_merge;
use function dirname;
use function escapeshellarg;
use function exec;
use function getenv;
use function implode;
use function ksort;
use function Safe\chdir;
use function Safe\file_put_contents;
use function Safe\getcwd;
use function Safe\json_encode;
use function Safe\realpath;
use function set_error_handler;
use function sprintf;

use const E_NOTICE;
use const E_STRICT;
use const E_WARNING;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const PHP_EOL;

(static function (): void {
    require_once __DIR__ . '/vendor/autoload.php';

    /**
     * @psalm-param callable(): ReturnType $function
     *
     * @psalm-return ReturnType
     *
     * @psalm-template ReturnType of mixed|void
     */
    function runInPath(callable $function, string $path): mixed
    {
        $originalPath = getcwd();

        chdir($path);

        try {
            $returnValue = $function();
        } finally {
            chdir($originalPath);
        }

        return $returnValue;
    }

    set_error_handler(
        static function (int $errorCode, string $message = '', string $file = '', int $line = 0): bool {
            throw new ErrorException($message, 0, $errorCode, $file, $line);
        },
        E_STRICT | E_NOTICE | E_WARNING
    );

    $token                     = getenv('GITHUB_TOKEN') ?: '';
    $authentication            = $token === '' ? '' : $token . ':x-oauth-basic@';
    $advisoriesRepository      = 'https://' . $authentication . 'github.com/FriendsOfPHP/security-advisories.git';
    $roaveAdvisoriesRepository = 'https://' . $authentication . 'github.com/Roave/SecurityAdvisories.git';
    $buildDir                  = __DIR__ . '/build';
    $baseComposerJson          = [
        'name'        => 'roave/security-advisories',
        'type'        => 'metapackage',
        'description' => 'Prevents installation of composer packages with known security vulnerabilities: '
            . 'no API, simply require it',
        'license'     => 'MIT',
        'authors'     => [
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

    $execute =
        /** @return non-empty-list<string> */
        static function (string $commandString): array {
            // may the gods forgive me for this in-lined command addendum, but I CBA to fix proc_open's handling
            // of exit codes.
            exec($commandString . ' 2>&1', $output, $result);

            if ($result !== 0) {
                throw new UnexpectedValueException(sprintf(
                    'Command failed: "%s" "%s"',
                    $commandString,
                    implode(PHP_EOL, $output)
                ));
            }

            /** @psalm-var non-empty-list<string> $output */
            return $output;
        };

    $cleanBuildDir = static function () use ($buildDir, $execute): void {
        $execute('rm -rf ' . escapeshellarg($buildDir));
        $execute('mkdir ' . escapeshellarg($buildDir));
    };

    $cloneAdvisories = static function () use ($advisoriesRepository, $buildDir, $execute): void {
        $execute(
            'git clone '
            . escapeshellarg($advisoriesRepository)
            . ' ' . escapeshellarg($buildDir . '/security-advisories')
        );
    };

    $cloneRoaveAdvisories = static function () use ($roaveAdvisoriesRepository, $buildDir, $execute): void {
        $execute(
            'git clone '
            . escapeshellarg($roaveAdvisoriesRepository)
            . ' ' . escapeshellarg($buildDir . '/roave-security-advisories')
        );

        $execute(sprintf(
            'cp -r %s %s',
            escapeshellarg($buildDir . '/roave-security-advisories'),
            escapeshellarg($buildDir . '/roave-security-advisories-original')
        ));
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
                $conflicts[$component->name->packageName] = $component->getConflictConstraint();
            }

            ksort($conflicts);

            return array_filter($conflicts);
        };

    $buildConflictsJson = static function (array $baseConfig, array $conflicts): string {
        return json_encode(
            array_merge(
                $baseConfig,
                ['conflict' => $conflicts]
            ),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    };

    $writeJson = static function (string $jsonString, string $path): void {
        file_put_contents($path, $jsonString . "\n");
    };

    $validateComposerJson = static function (string $composerJsonPath) use ($execute): void {
        runInPath(
            static function () use ($execute): void {
                $execute('composer validate');
            },
            dirname($composerJsonPath)
        );
    };

    $copyGeneratedComposerJson = static function (
        string $sourceComposerJsonPath,
        string $targetComposerJsonPath
    ) use ($execute): void {
        $execute(sprintf(
            'cp %s %s',
            escapeshellarg($sourceComposerJsonPath),
            escapeshellarg($targetComposerJsonPath)
        ));
    };

    $commitComposerJson = static function (string $composerJsonPath) use ($execute): void {
        $parseHead =
            /** @psalm-return non-empty-list<string> */
            static function () use ($execute): array {
                return $execute('git rev-parse HEAD');
            };
        $originalHash = runInPath(
            $parseHead,
            dirname($composerJsonPath) . '/../security-advisories'
        );

        runInPath(
            static function () use ($composerJsonPath, $originalHash, $execute): void {
                $execute('git add ' . escapeshellarg(realpath($composerJsonPath)));

                $message  = sprintf(
                    'Committing generated "composer.json" file as per "%s"',
                    (new DateTime('now', new DateTimeZone('UTC')))->format(DateTime::W3C)
                );
                $message .= "\n" . sprintf(
                    'Original commit: "%s"',
                    'https://github.com/FriendsOfPHP/security-advisories/commit/' . $originalHash[0]
                );

                $execute('git diff-index --quiet HEAD || git commit -m ' . escapeshellarg($message));
            },
            dirname($composerJsonPath)
        );
    };

// cleanup:
    $cleanBuildDir();
    $cloneAdvisories();
    $cloneRoaveAdvisories();

    $getAdvisories = (new GetAdvisoriesFromMultipleSources(
        (new GetAdvisoriesFromFriendsOfPhp($buildDir . '/security-advisories')),
        (new GetAdvisoriesFromGithubApi(
            new Client(),
            $token,
        )),
    ));

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

    $copyGeneratedComposerJson(
        __DIR__ . '/build/composer.json',
        __DIR__ . '/build/roave-security-advisories/composer.json'
    );
    $commitComposerJson(__DIR__ . '/build/roave-security-advisories/composer.json');
})();
