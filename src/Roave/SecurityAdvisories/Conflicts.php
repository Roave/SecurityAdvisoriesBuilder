<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use function array_key_exists;
use function Psl\Str\split;

/*
 * basically a representation of current composer json file
 */
final class Conflicts
{
    private array $conflictsMap;

    private function __construct()
    {
    }

    public static function fromArray(array $packageConflictsParsedData): self
    {
        $packageConflicts = [];
        // so here we have pure/refined/de-duplicated advisories
        foreach ($packageConflictsParsedData as $referenceName => $v) {
            $packageConstraints = [];
            foreach (split($v, '|') as $range) {
                $packageConstraints[] = VersionConstraint::fromString($range);
            }

            $packageConflicts[$referenceName] = $packageConstraints;
        }

        $conflicts               = new self();
        $conflicts->conflictsMap = $packageConflicts;

        return $conflicts;
    }

    // todo: change naming
    public function filterNewAdvisories(iterable $advisories): iterable
    {
        foreach ($advisories as $newAdvisory) {
            $pkgName = $newAdvisory->package->packageName;

            if (! array_key_exists($pkgName, $this->conflictsMap)) {
                continue;
            }

            if (! $this->isAdvisoryUpdate($newAdvisory, $this->conflictsMap[$pkgName])) {
                continue;
            }

            yield $newAdvisory;
        }
    }

    /**
     * @param VersionConstraint[] $currentConstraints
     */
    private function isAdvisoryUpdate(Advisory $newAdvisory, array $currentConstraints): bool
    {
        foreach ($newAdvisory->getVersionConstraints() as $newConstraint) {
            if (! $this->contains($newConstraint, $currentConstraints)) {
                return true;
            }
        }

        return false;
    }

    private function contains(VersionConstraint $newConstraint, $currentConstraints): bool
    {
        foreach ($currentConstraints as $currConstraint) {
            if ($currConstraint->contains($newConstraint)) {
                return true;
            }
        }

        return false;
    }
}

/*
    foreach ($getAdvisories() as $newAdvisory) {
        $currentAdvisoryConstraints = $currentConstraints[$newAdvisory->package->packageName];
        $newAdvisoryConstraints     = $newAdvisory->getVersionConstraints();

        // now check that new advisory constraints are all included into current advisory constraints
        // in other words, check that there is no range expansion OR new ranges added

        $isUpdate = false;
        // check every new constr agains all old constraints
        foreach ($newAdvisoryConstraints as $newConstraint) {
            if ($isExpansion($newConstraint, $currentAdvisoryConstraints)) {
                $isUpdate = true;
                break;
            }
        }

        if (! $isUpdate) {
            continue;
        }

        // this is something new, either completely new range, or extension, or deletion(?)
        $updatedAdvisories[] = $newAdvisory;
    }

 */
