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

use LogicException;

use function array_filter;
use function array_map;
use function array_merge;
use function array_values;
use function count;
use function implode;
use function usort;

/** @psalm-immutable */
final class Component
{
    private string $name;

    /**
     * @var Advisory[]
     * @psalm-var list<Advisory>
     */
    private array $advisories;

    public function __construct(string $name, Advisory ...$advisories)
    {
        $this->name       = $name;
        $this->advisories = $advisories;
    }

    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @throws LogicException
     */
    public function getConflictConstraint(): string
    {
        return implode(
            '|',
            array_filter(array_map(
                static function (VersionConstraint $versionConstraint) {
                    return $versionConstraint->getConstraintString();
                },
                $this->deDuplicateConstraints(array_merge(
                    [],
                    ...array_values(array_map(
                        static function (Advisory $advisory) {
                            return $advisory->getVersionConstraints();
                        },
                        $this->advisories
                    ))
                ))
            ))
        );
    }

    /**
     * @param VersionConstraint[] $constraints
     *
     * @return list<VersionConstraint>
     *
     * @throws LogicException
     */
    private function deDuplicateConstraints(array $constraints): array
    {
        $inputConstraintsByName = [];

        foreach ($constraints as $constraint) {
            $inputConstraintsByName[$constraint->getConstraintString()] = $constraint;
        }

        $merged = array_map(
            static fn (VersionConstraint $item) => \array_reduce(
                $constraints,
                static fn (VersionConstraint $carry, VersionConstraint $current) => $carry->canMergeWith($current)
                    ? $carry->mergeWith($current)
                    : $carry,
                $item
            ),
            $inputConstraintsByName
        );

        $mergedConstraintsByName = [];

        foreach ($merged as $constraint) {
            $mergedConstraintsByName[$constraint->getConstraintString()] = $constraint;
        }

        // All constraints were merged together
        if (count($inputConstraintsByName) === count($mergedConstraintsByName)) {
            /** @psalm-suppress ImpureFunctionCall this sorting function is operating in a pure manner */
            usort($merged, new VersionConstraintSort());

            return array_values($merged);
        }

        // Recursion: one de-duplication did not suffice
        return $this->deDuplicateConstraints($merged);
    }
}
