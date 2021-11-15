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

use Psl\Str;
use Psl\Type;
use Psl\Vec;
use Roave\SecurityAdvisories\Exception\InvalidPackageName;

/** @psalm-immutable */
final class Advisory
{
    public PackageName $package;

    /** @var list<VersionConstraint> */
    private array $branchConstraints;

    /** @param list<VersionConstraint> $branchConstraints */
    private function __construct(PackageName $package, array $branchConstraints)
    {
        $this->package           = $package;
        $this->branchConstraints = $this->sortVersionConstraints($branchConstraints);
    }

    /**
     * @psalm-param array{
     *     branches: array<array-key, array{versions: string|array<array-key, string>}>,
     *     reference: string
     * } $config
     *
     * @return Advisory
     *
     * @throws InvalidPackageName
     * @throws Type\Exception\CoercionException
     *
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    public static function fromArrayData(array $config): self
    {
        return new self(
            PackageName::fromReferenceName($config['reference']),
            Vec\map(
                $config['branches'],
                /**
                 * @param array{versions: string|array<array-key, string>} $branchConfig
                 */
                static function (array $branchConfig): VersionConstraint {
                    $versions = $branchConfig['versions'];
                    if (Type\string()->matches($versions)) {
                        $versions = [$versions];
                    }

                    return VersionConstraint::fromString(Str\join(Vec\values($versions), ','));
                }
            )
        );
    }

    /**
     * @return list<VersionConstraint>
     */
    public function getVersionConstraints(): array
    {
        return $this->branchConstraints;
    }

    /**
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    public function getConstraint(): ?string
    {
        // @TODO may want to escape this
        return Str\join(
            Vec\map(
                $this->branchConstraints,
                static fn (VersionConstraint $versionConstraint) => $versionConstraint->getConstraintString()
            ),
            '|'
        ) ?: null;
    }

    /**
     * @param VersionConstraint[] $versionConstraints
     *
     * @return VersionConstraint[]
     * @psalm-return list<VersionConstraint>
     */
    private function sortVersionConstraints(array $versionConstraints): array
    {
        /** @psalm-suppress ImpureFunctionCall this sorting function is operating in a pure manner */
        return Vec\sort($versionConstraints, new VersionConstraintSort());
    }
}
