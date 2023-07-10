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

namespace Roave\SecurityAdvisories\Rule;

use Roave\SecurityAdvisories\Advisory;

final class RuleProviderFactory
{
    private const REPLACEMENTS = [
        'https://github.com/advisories/GHSA-c9r9-3h38-r7vj has a buggy version name' => [
            'package' => 'zencart/zencart',
            'originalConstraint' => '< 1.5.5e',
            'replacementConstraint' => '<1.5.8', // safe to use, no weird version naming
        ],
        'https://github.com/advisories/GHSA-38f9-4vhq-9cr8 has a buggy version name' => [
            'package' => 'zencart/zencart',
            'originalConstraint' => '<= 1.5.7b',
            'replacementConstraint' => '<1.5.8', // safe to use, no weird version naming
        ],
        'https://github.com/advisories/GHSA-wxxx-2x6v-979f has a buggy version name' => [
            'package' => 'zencart/zencart',
            'originalConstraint' => '< 1.5.7a',
            'replacementConstraint' => '<1.5.8', // safe to use, no weird version naming
        ],
        'too aggressive `laminas/laminas-form` affected range in published advisory' => [
            'package' => 'laminas/laminas-form',
            'originalConstraint' => '<2.17.2',
            'replacementConstraint' => '<2.17.1',
        ],
    ];

    /** @psalm-return list<callable(Advisory): Advisory> */
    public function __invoke(): array
    {
        return [
            static function (Advisory $advisory): Advisory {
                foreach (
                    self::REPLACEMENTS as [
                        'package' => $packageName,
                        'originalConstraint' => $targetConstraint,
                        'replacementConstraint' => $replacementConstraint,
                    ]
                ) {
                    if (
                        $advisory->package->packageName !== $packageName
                        || $advisory->getConstraint() !== $targetConstraint
                    ) {
                        continue;
                    }

                    return Advisory::fromArrayData([
                        'reference' => $packageName,
                        'branches' => [
                            ['versions' => [$replacementConstraint]],
                        ],
                    ]);
                }

                return $advisory;
            },
        ];
    }
}
