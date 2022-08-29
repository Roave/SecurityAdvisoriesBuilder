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

use CallbackFilterIterator;
use FilesystemIterator;
use Generator;
use Psl\File;
use Psl\Str;
use Psl\Type;
use Psl\Vec;
use RecursiveDirectoryIterator;
use RecursiveFilterIterator;
use RecursiveIterator;
use RecursiveIteratorIterator;
use Roave\SecurityAdvisories\Advisory;
use SplFileInfo;
use Symfony\Component\Yaml\Yaml;

final class GetAdvisoriesFromFriendsOfPhp implements GetAdvisories
{
    private const ADVISORY_EXTENSION = 'yaml';

    public function __construct(private string $advisoriesPath)
    {
    }

    /** @return Generator<Advisory> */
    public function __invoke(): Generator
    {
        $advisoryDefinition = Type\shape([
            'branches' => Type\dict(Type\array_key(), Type\shape([
                'versions' => Type\union(Type\string(), Type\vec(Type\string())),
            ], true)),
            'reference' => Type\string(),
        ], true);

        return yield from Vec\map(
            $this->getAdvisoryFiles(),
            static function (SplFileInfo $advisoryFile) use ($advisoryDefinition): Advisory {
                $definition = $advisoryDefinition->assert(Yaml::parse(
                    File\read(Type\non_empty_string()
                        ->assert($advisoryFile->getRealPath())),
                    Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE,
                ));

                return Advisory::fromArrayData($definition);
            },
        );
    }

    /** @return iterable<SplFileInfo> */
    private function getAdvisoryFiles(): iterable
    {
        return new CallbackFilterIterator(
            new RecursiveIteratorIterator(
                $this->skipHiddenFilesAndDirectories(
                    new RecursiveDirectoryIterator($this->advisoriesPath, FilesystemIterator::SKIP_DOTS),
                ),
            ),
            static function (SplFileInfo $advisoryFile): bool {
                return $advisoryFile->isFile()
                    && $advisoryFile->getExtension() === self::ADVISORY_EXTENSION;
            },
        );
    }

    private function skipHiddenFilesAndDirectories(RecursiveIterator $files): RecursiveIterator
    {
        return new class ($files) extends RecursiveFilterIterator {
            public function accept(): bool
            {
                return ! Str\starts_with(
                    Type\instance_of(SplFileInfo::class)
                        ->assert($this->current())
                        ->getFilename(),
                    '.',
                );
            }
        };
    }
}
