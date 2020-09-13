<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class VersionConstraintSort
{
    public function __invoke(VersionConstraint $a, VersionConstraint $b): int
    {
        $versionA = $a->getLowerBound() ?? $a->getUpperBound();
        $versionB = $b->getLowerBound() ?? $b->getUpperBound();

        if (isset($versionA, $versionB)) {
            if ($versionA->isGreaterThan($versionB)) {
                return 1;
            }

            if ($versionB->isGreaterThan($versionA)) {
                return -1;
            }
        }

        return 0;
    }
}
