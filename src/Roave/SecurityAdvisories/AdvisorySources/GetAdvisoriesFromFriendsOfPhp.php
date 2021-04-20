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
use RecursiveDirectoryIterator;
use RecursiveFilterIterator;
use RecursiveIterator;
use RecursiveIteratorIterator;
use Roave\SecurityAdvisories\Advisory;
use SplFileInfo;
use Symfony\Component\Yaml\Yaml;
use Webmozart\Assert\Assert;

use function array_map;
use function assert;
use function is_string;
use function iterator_to_array;
use function Safe\file_get_contents;
use function str_starts_with;

final class GetAdvisoriesFromFriendsOfPhp implements GetAdvisories
{
    private const ADVISORY_EXTENSION = 'yaml';

    private string $advisoriesPath;

    public function __construct(string $advisoriesPath)
    {
        $this->advisoriesPath = $advisoriesPath;
    }

    /**
     * @return Generator<Advisory>
     */
    public function __invoke(): Generator
    {
        return yield from array_map(
            static function (SplFileInfo $advisoryFile): Advisory {
                $filePath = $advisoryFile->getRealPath();

                assert(is_string($filePath));

                /** @psalm-var array<array-key, array<array-key, array<array-key, array<array-key, string>|string>>|string> $definition */
                $definition = Yaml::parse(file_get_contents($filePath), Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);

                return Advisory::fromArrayData($definition);
            },
            $this->getAdvisoryFiles()
        );
    }

    /**
     * @return SplFileInfo[]
     */
    private function getAdvisoryFiles(): array
    {
        return iterator_to_array(new CallbackFilterIterator(
            new RecursiveIteratorIterator(
                $this->skipHiddenFilesAndDirectories(
                    new RecursiveDirectoryIterator($this->advisoriesPath, FilesystemIterator::SKIP_DOTS)
                ),
            ),
            static function (SplFileInfo $advisoryFile): bool {
                return $advisoryFile->isFile()
                    && $advisoryFile->getExtension() === self::ADVISORY_EXTENSION;
            }
        ));
    }

    private function skipHiddenFilesAndDirectories(RecursiveIterator $files): RecursiveIterator
    {
        return new class ($files) extends RecursiveFilterIterator {
            public function accept(): bool
            {
                $current = $this->current();

                Assert::isInstanceOf($current, SplFileInfo::class);

                return ! str_starts_with($current->getFilename(), '.');
            }
        };
    }
}
