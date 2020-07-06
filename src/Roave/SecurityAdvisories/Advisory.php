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

use InvalidArgumentException;
use function array_map;
use function array_values;
use function assert;
use function implode;
use function is_array;
use function is_string;
use function Safe\usort;
use function str_replace;

final class Advisory
{
    private string $componentName;

    /**
     * @var VersionConstraint[]
     * @psalm-var list<VersionConstraint>
     */
    private array $branchConstraints;

    /**
     * @param VersionConstraint[] $branchConstraints
     */
    private function __construct(string $componentName, array $branchConstraints)
    {
        /** @psalm-var callable(...VersionConstraint): list<VersionConstraint>|null $checkType */
        static $checkType;

        $checkType = $checkType ?: static function (VersionConstraint ...$versionConstraints) : array {
            return $versionConstraints;
        };

        $this->componentName     = $componentName;
        $this->branchConstraints = $this->sortVersionConstraints($checkType(...$branchConstraints));
    }

    /**
     * @param string[]|string[][][]|string[][][][] $config
     *
     * @return Advisory
     *
     * @throws InvalidArgumentException
     *
     * @psalm-suppress RedundantCondition
     */
    public static function fromArrayData(array $config) : self
    {
        /** @var string $reference */
        $reference = $config['reference'];
        $componentName = str_replace('composer://', '', $reference);
        $branches      = $config['branches'];

        assert(is_string($componentName));
        assert(is_array($branches));

        return new self(
            $componentName,
            array_values(array_map(
                static function (array $branchConfig) {
                    return VersionConstraint::fromString(implode(',', (array) $branchConfig['versions']));
                },
                $branches
            ))
        );
    }

    public function getComponentName() : string
    {
        return $this->componentName;
    }

    /**
     * @return VersionConstraint[]
     */
    public function getVersionConstraints() : array
    {
        return $this->branchConstraints;
    }

    public function getConstraint() : ?string
    {
        // @TODO may want to escape this
        return implode(
            '|',
            array_map(
                static function (VersionConstraint $versionConstraint) {
                    return $versionConstraint->getConstraintString();
                },
                $this->branchConstraints
            )
        ) ?: null;
    }

    /**
     * @param VersionConstraint[] $versionConstraints
     *
     * @return VersionConstraint[]
     *
     * @psalm-return list<VersionConstraint>
     */
    private function sortVersionConstraints(array $versionConstraints) : array
    {
        usort($versionConstraints, new VersionConstraintSort());

        return $versionConstraints;
    }
}
