<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use function array_key_exists;
use function Psl\Str\split;

final class ConstraintsMap
{
    /** @var array  */
    private array $map;

    private function __construct()
    {
    }

    public static function fromArray(array $packageConflictsParsedData): self
    {
        $packageConflicts = [];

        foreach ($packageConflictsParsedData as $referenceName => $v) {
            $packageConstraints = [];
            foreach (split($v, '|') as $range) {
                $packageConstraints[] = VersionConstraint::fromString($range);
            }

            $packageConflicts[$referenceName] = $packageConstraints;
        }

        $conflicts = new self();
        $conflicts->map = $packageConflicts;

        return $conflicts;
    }

    // todo: change naming
    public function advisoriesDiff(iterable $advisoriesToFilter): array
    {
        $filteredAdvisories = [];

        /** @var Advisory $advisoryToFilter */
        foreach ($advisoriesToFilter as $advisoryToFilter) { // iterate over new advisories
            $pkgNameKey = $advisoryToFilter->package->packageName;

            $isNewAdvisory = !array_key_exists($pkgNameKey, $this->map);

            if ($isNewAdvisory) {
                $filteredAdvisories[] = $advisoryToFilter;
                continue;
            }

            $isUpdateAdvisory = $this->isAdvisoryUpdate($pkgNameKey, $advisoryToFilter);

            if ($isUpdateAdvisory) {
                $filteredAdvisories[] = $advisoryToFilter;
            }
        }

        return $filteredAdvisories;
    }

    private function isAdvisoryUpdate(string $pkgNameKey, Advisory $advisoryToCheck): bool
    {
        $packageConstraints = $this->map[$pkgNameKey];

        /** @var VersionConstraint $advisoryConstraint */
        foreach ($advisoryToCheck->getVersionConstraints() as $advisoryConstraint) {
            $included = false;
            /** @var VersionConstraint $pkgConstraint */
            foreach ($packageConstraints as $pkgConstraint) {

                if ($pkgConstraint->equalOrIncludes($advisoryConstraint)) {
                    $included = true;
                    break;
                }
            }
            if (!$included) {
                return true;
            }
        }

        return false;
    }
}
