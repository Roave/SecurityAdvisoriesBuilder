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
use Generator;
use Http\Client\Curl\Client;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromFriendsOfPhp;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromGithubApi;
use Roave\SecurityAdvisories\AdvisorySources\GetAdvisoriesFromMultipleSources;
use UnexpectedValueException;
use const E_NOTICE;
use const E_STRICT;
use const E_WARNING;
use const JSON_PRETTY_PRINT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const PHP_EOL;
use function array_filter;
use function array_merge;
use function assert;
use function dirname;
use function escapeshellarg;
use function exec;
use function getenv;
use function implode;
use function is_string;
use function Safe\chdir;
use function Safe\file_put_contents;
use function Safe\getcwd;
use function Safe\json_encode;
use function Safe\ksort;
use function Safe\realpath;
use function Safe\sprintf;
use function set_error_handler;

(static function () : void {
    require_once __DIR__ . '/vendor/autoload.php';

    set_error_handler(
        static function ($errorCode, $message = '', $file = '', $line = 0) : bool {
            throw new ErrorException($message, 0, $errorCode, $file, $line);
        },
        E_STRICT | E_NOTICE | E_WARNING
    );

    $token = getenv('GITHUB_TOKEN') ?? '';

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

    $argsToString = fn(string ...$args) : string =>
        sprintf('%s %s' , array_shift($args), join(' ', array_map('escapeshellarg', $args)));

    $execute = static function (string $commandString) : array {
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

        return $output;
    };

    $cleanBuildDir = static fn ()  : array =>
        array_map(
            $execute,
            [
                $argsToString('rm -rf', $buildDir),
                $argsToString('mkdir', $buildDir)
            ]
        );

    $cloneAdvisories = static fn () : array  =>
        $execute($argsToString('git clone', $advisoriesRepository, $buildDir . '/security-advisories'));

    $cloneRoaveAdvisories = static fn () : array =>
        array_map(
            $execute,
            [
                $argsToString('git clone', $roaveAdvisoriesRepository, $buildDir . '/roave-security-advisories'),
                $argsToString('cp -r', $buildDir . '/roave-security-advisories', $buildDir . '/roave-security-advisories-original')
            ]
        );

    /**
     * @param Generator<Advisory> $getAdvisories
     *
     * @return Component[]
     */
    $buildComponents = static function (Generator $advisories) : array {
        // @todo need a functional way to do this, somehow
        $indexedAdvisories = [];
        $components        = [];

        foreach ($advisories as $advisory) {
            if (! isset($indexedAdvisories[$advisory->getComponentName()])) {
                $indexedAdvisories[$advisory->getComponentName()] = [];
            }

            $indexedAdvisories[$advisory->getComponentName()][] = $advisory;
        }

        foreach ($indexedAdvisories as $componentName => $componentAdvisories) {
            $components[$componentName] = new Component($componentName, ...$componentAdvisories);
        }

        return $components;
    };

    /**
     * @param Component[] $components
     *
     * @return string[]
     */
    $buildConflicts = static function (array $components) : array {
        $conflicts = [];

        foreach ($components as $component) {
            $conflicts[$component->getName()] = $component->getConflictConstraint();
        }

        ksort($conflicts);

        return array_filter($conflicts);
    };

    $buildConflictsJson = static fn (array $baseConfig, array $conflicts) : string =>
        json_encode(
            array_merge(
                $baseConfig,
                ['conflict' => $conflicts]
            ),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );

    $writeJson = static fn (string $jsonString, string $path) : int =>
        file_put_contents($path, $jsonString . "\n");

    $runInPath = static function (callable $function, string $path) {
        $originalPath = getcwd();

        chdir($path);

        try {
            $returnValue = $function();
        } finally {
            chdir($originalPath);
        }

        return $returnValue;
    };

    $getComposerPhar = static function (string $targetDir) use ($runInPath, $execute) : void {
        $runInPath(
            static function () use ($targetDir, $execute) : void {
                $installerPath = escapeshellarg($targetDir . '/composer-installer.php');

                $execute(sprintf(
                    'curl -sS https://getcomposer.org/installer -o %s && php %s',
                    $installerPath,
                    $installerPath
                ));
            },
            $targetDir
        );
    };

    $validateComposerJson = static function (string $composerJsonPath) use ($runInPath, $execute) : void {
        $runInPath(
            static function () use ($execute) : void {
                $execute('php composer.phar validate');
            },
            dirname($composerJsonPath)
        );
    };

    $copyGeneratedComposerJson = static fn(
        string $sourceComposerJsonPath,
        string $targetComposerJsonPath
    ) : array => $execute(
        $argsToString(
            'cp',
            $sourceComposerJsonPath,
            $targetComposerJsonPath
        )
    );

    $commitComposerJson = static function (string $composerJsonPath) use ($runInPath, $execute) : void {
        $originalHash = $runInPath(
            static function () use ($execute) {
                return $execute('git rev-parse HEAD');
            },
            dirname($composerJsonPath) . '/../security-advisories'
        );

        $runInPath(
            static function () use ($composerJsonPath, $originalHash, $execute) : void {
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

    $getComposerPhar(__DIR__ . '/build');
    $validateComposerJson(__DIR__ . '/build/composer.json');

    $copyGeneratedComposerJson(
        __DIR__ . '/build/composer.json',
        __DIR__ . '/build/roave-security-advisories/composer.json'
    );
    $commitComposerJson(__DIR__ . '/build/roave-security-advisories/composer.json');
})();
