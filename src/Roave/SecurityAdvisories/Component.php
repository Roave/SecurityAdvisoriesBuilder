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
use Psl\Vec;

use function array_map;
use function array_merge;
use function array_reduce;
use function Psl\Type\instance_of;
use function Psl\Type\non_empty_vec;

/** @psalm-immutable */
final class Component
{
    /** @param non-empty-list<Advisory> $advisories */
    public function __construct(public readonly PackageName $name, private readonly array $advisories)
    {
    }

    /** @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130} */
    public function getConflictConstraint(): string
    {
        /** @psalm-suppress ImpureFunctionCall,ImpureMethodCall sorting + assertions are operating in a pure manner */
        $advisories = Vec\sort(
            non_empty_vec(instance_of(VersionConstraint::class))
                ->assert(array_merge([], ...array_map(
                    static fn (Advisory $advisory): array => $advisory->getVersionConstraints(),
                    $this->advisories,
                ))),
            Closure::fromCallable([VersionConstraint::class, 'sort']),
        );

        return array_reduce(
            Vec\slice($advisories, 1),
            static fn (VersionConstraint $a, VersionConstraint $b): VersionConstraint => $a->mergeWith($b),
            $advisories[0],
        )->getConstraintString();
    }
}
