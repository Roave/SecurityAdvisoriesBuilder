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
use function implode;
use function Safe\usort;

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

    public function getName() : string
    {
        return $this->name;
    }

    /**
     * @throws LogicException
     */
    public function getConflictConstraint() : string
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
     * @return VersionConstraint[]
     *
     * @throws LogicException
     */
    private function deDuplicateConstraints(array $constraints) : array
    {
        restart:

        foreach ($constraints as & $constraint) {
            foreach ($constraints as $key => $comparedConstraint) {
                if ($constraint === $comparedConstraint || ! $constraint->canMergeWith($comparedConstraint)) {
                    continue;
                }

                unset($constraints[$key]);
                $constraint = $constraint->mergeWith($comparedConstraint);

                // note: this is just simulating tail recursion. Normal recursion not viable here, and `foreach`
                //       becomes unstable when elements are removed from the loop
                goto restart;
            }
        }

        usort($constraints, new VersionConstraintSort());

        return $constraints;
    }
}
