<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories\Helper;

use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\VersionConstraint;

use function array_key_exists;
use function Psl\Str\split;

final class ConstraintsMap
{
    /** @var array<string, array<VersionConstraint>> $map */
    private array $map;

    /**
     * @param array<string, array<VersionConstraint>> $conflicts
     */
    private function __construct(array $conflicts)
    {
        $this->map = $conflicts;
    }

    /**
     * @param array<string, string> $packageConflictsParsedData
     *
     * @return ConstraintsMap
     */
    public static function fromArray(array $packageConflictsParsedData): self
    {
        $packageConflicts = [];

        foreach ($packageConflictsParsedData as $referenceName => $constraintsString) {
            $packageConstraints = [];
            foreach (split($constraintsString, '|') as $range) {
                $packageConstraints[] = VersionConstraint::fromString($range);
            }

            $packageConflicts[$referenceName] = $packageConstraints;
        }

        return new self($packageConflicts);
    }

    /**
     * @param array<Advisory> $advisoriesToFilter
     *
     * @return array<Advisory>
     */
    public function advisoriesDiff(array $advisoriesToFilter): array
    {
        $filteredAdvisories = [];

        foreach ($advisoriesToFilter as $advisoryToFilter) {
            $pkgNameKey = $advisoryToFilter->package->packageName;

            $isNewAdvisory = ! array_key_exists($pkgNameKey, $this->map);

            if ($isNewAdvisory) {
                $filteredAdvisories[] = $advisoryToFilter;
                continue;
            }

            $isUpdateAdvisory = $this->isAdvisoryUpdate($pkgNameKey, $advisoryToFilter);

            if (! $isUpdateAdvisory) {
                continue;
            }

            $filteredAdvisories[] = $advisoryToFilter;
        }

        return $filteredAdvisories;
    }

    private function isAdvisoryUpdate(string $packageName, Advisory $advisoryToCheck): bool
    {
        $packageConstraints = $this->map[$packageName];

        foreach ($advisoryToCheck->getVersionConstraints() as $advisoryConstraint) {
            $included = false;
            foreach ($packageConstraints as $pkgConstraint) {
                if ($pkgConstraint->contains($advisoryConstraint)) {
                    $included = true;
                    break;
                }
            }

            if (! $included) {
                return true;
            }
        }

        return false;
    }
}
