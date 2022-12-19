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

use Closure;
use Psl\Iter;
use Psl\Str;
use Psl\Vec;

use function array_map;
use function array_merge;

/** @psalm-immutable */
final class Component
{
    /** @var Advisory[] */
    private array $advisories;

    public function __construct(public PackageName $name, Advisory ...$advisories)
    {
        $this->advisories = $advisories;
    }

    /** @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130} */
    public function getConflictConstraint(): string
    {
        return Str\join(Vec\filter(Vec\map(
            $this->deDuplicateConstraints(array_merge([], ...array_map(
                static fn (Advisory $advisory) => $advisory->getVersionConstraints(),
                $this->advisories,
            ))),
            static fn (VersionConstraint $versionConstraint) => $versionConstraint->getConstraintString(),
        )), '|');
    }

    /**
     * @param list<VersionConstraint> $constraints
     *
     * @return list<VersionConstraint>
     *
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    private function deDuplicateConstraints(array $constraints): array
    {
        $inputConstraintsByName = [];

        foreach ($constraints as $constraint) {
            $inputConstraintsByName[$constraint->getConstraintString()] = $constraint;
        }

        $merged = Vec\map(
            $inputConstraintsByName,
            static fn (VersionConstraint $item) => Iter\reduce(
                $constraints,
                static fn (VersionConstraint $carry, VersionConstraint $current) => $carry->canMergeWith($current)
                    ? $carry->mergeWith($current)
                    : $carry,
                $item,
            ),
        );

        $mergedConstraintsByName = [];

        foreach ($merged as $constraint) {
            $mergedConstraintsByName[$constraint->getConstraintString()] = $constraint;
        }

        // All constraints were merged together
        if (Iter\count($inputConstraintsByName) === Iter\count($mergedConstraintsByName)) {
            /** @psalm-suppress ImpureFunctionCall this sorting function is operating in a pure manner */
            return Vec\sort($merged, Closure::fromCallable(new VersionConstraintSort()));
        }

        // Recursion: one de-duplication did not suffice
        return $this->deDuplicateConstraints($merged);
    }
}
