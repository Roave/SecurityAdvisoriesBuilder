<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Roave\SecurityAdvisories\Exception\InvalidPackageName;

use function preg_match;
use function Psl\Type\non_empty_string;
use function str_replace;

/**
 * Small value type around the definition of a package name.
 *
 * @see https://github.com/composer/composer/blob/c4c5647110d62b1f90097e21cb65a114349f33e1/src/Composer/Package/Loader/ValidatingArrayLoader.php#L379
 *
 * @psalm-immutable
 */
final class PackageName
{
    /** @var non-empty-string */
    public string $packageName;

    /** @param non-empty-string $packageName */
    private function __construct(string $packageName)
    {
        $this->packageName = $packageName;
    }

    /**
     * @throws InvalidPackageName
     *
     * @psalm-pure
     *
     * @psalm-suppress ImpureFunctionCall see https://github.com/azjezz/psl/issues/130
     * @psalm-suppress ImpureMethodCall see https://github.com/azjezz/psl/issues/130
     */
    public static function fromName(string $name): self
    {
        if (preg_match('{^[a-z0-9](?:[_.-]?[a-z0-9]+)*/[a-z0-9](?:(?:[_.]?|-{0,2})[a-z0-9]+)*$}iD', $name) !== 1) {
            throw InvalidPackageName::fromInvalidName($name);
        }

        return new self(
            non_empty_string()
                ->coerce($name)
        );
    }

    /**
     * @throws InvalidPackageName
     *
     * @psalm-pure
     */
    public static function fromReferenceName(string $reference): self
    {
        return self::fromName(str_replace(
            ['composer://', '\\'],
            ['', '/'],
            $reference
        ));
    }
}
