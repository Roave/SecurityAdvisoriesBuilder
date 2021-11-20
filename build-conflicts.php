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
use Roave\SecurityAdvisories\Rule\RuleProviderFactory;

use function Psl\Type\array_key;
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
        // why do we need a copy ?
//        Shell\execute(
//            'cp',
//            ['-r', $buildDir . '/roave-security-advisories', $buildDir . '/roave-security-advisories-original']
//        );
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

        if (count($addedAdvisories) > 0) {
            $message .= "\n\nAdded advisories:";

            foreach ($addedAdvisories as $advisory) {
                $message .= "\n" . Str\format(
                        '   Package name: "%s"',
                        $advisory->package->packageName,
                    );
                $message .= "\n" . Str\format(
                        '   Summary: "%s"',
                        $advisory->source->summary,
                    );
                $message .= "\n" . Str\format(
                        '   URI: "%s"',
                        $advisory->source->uri,
                    );
                $message .= "\n";
            }

            $message .= "\n";
        }

        print $message;



//        try {
//            Shell\execute('git', ['diff-index', '--quiet', 'HEAD'], $workingDirectory);
//        } catch (Shell\Exception\FailedExecutionException) {
//            Shell\execute('git', ['commit', '-m', $message], $workingDirectory);
//        }
    };

    // cleanup:
//    $cleanBuildDir();
//    $cloneAdvisories();
//    $cloneRoaveAdvisories();

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


//    echo "iterating";
//
//    foreach  ($getAdvisories() as $val ) {
//        var_dump($val);
//    }
//    sleep(10);
//    echo "Iterating";
//

    $a = file_get_contents( __DIR__ . '/build/roave-security-advisories/composer.json');
    $foo = json_decode($a, true);
    $prevConflicts = $foo['conflict'];
    $oldConflictPackages = array_keys($prevConflicts);


    $addedAdvisories = [];
    foreach  ($getAdvisories() as $val ) {
        if (!in_array($val->package->packageName, $oldConflictPackages, true)) {
            $addedAdvisories[] = $val;
        }
    }




//


    // actual work:
//    $writeJson(
//        $buildConflictsJson(
//            $baseComposerJson,
//            $buildConflicts(
//                $buildComponents(
//                    $getAdvisories()
//                )
//            )
//        ),
//        __DIR__ . '/build/composer.json'
//    );
//
//    $validateComposerJson(__DIR__ . '/build/composer.json');

//    $copyGeneratedComposerJson(
//        __DIR__ . '/build/composer.json',
//        __DIR__ . '/build/roave-security-advisories/composer.json'
//    );


//    $a = file_get_contents( __DIR__ . '/build/roave-security-advisories/composer.json');
//    $foo = json_decode($a, true);
//    $prevConflicts = $foo['conflict'];
////    foreach ($foo['conflict'] as $k => $v ) {
////        printf("%s %s \n", $k, $v);
////    }
//
//    echo '----------------------------------------------------------------------------------------------------------';
//
//    $b = file_get_contents( __DIR__ . '/build/composer.json');
//    $bar = json_decode($b, true);
//    $currConflicts = $bar['conflict'];
//    foreach ($bar['conflict'] as $k => $v ) {
//        printf("%s %s \n", $k, $v);
//    }


//    var_dump( array_diff_assoc($prevConflicts, $currConflicts));
//    var_dump(array_diff_key($bar['conflict'], $foo['conflict']));
//    var_dump(array_diff_key($foo['conflict'], $bar['conflict']));
//    var_dump($foo);

    // deleted in current
    // "3f/pygmentize": "<1.2",
    // updated in current
    // "adodb/adodb-php": "<6.20.12", // <----- updated vrom 5. to 6.

    // compare by key against current
    // shows what was deleted in current
//    var_dump(array_diff_key($prevConflicts, $currConflicts));

    // now try to get what value was changed in current
//    var_dump(array_diff_assoc($prevConflicts, $currConflicts));



    /*
     *  take two json files
     *  figure the diff what was deleted, what was appended, what is updated
     *  for each also show source and content
     *
     */


    $commitComposerJson(__DIR__ . '/build/roave-security-advisories/composer.json', $addedAdvisories);// pass here generated message
})();
