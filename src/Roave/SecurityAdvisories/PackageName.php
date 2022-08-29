<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Psl\Regex;
use Psl\Str;
use Psl\Type;
use Roave\SecurityAdvisories\Exception\InvalidPackageName;

/**
 * Small value type around the definition of a package name.
 *
 * @see https://github.com/composer/composer/blob/c4c5647110d62b1f90097e21cb65a114349f33e1/src/Composer/Package/Loader/ValidatingArrayLoader.php#L379
 *
 * @psalm-immutable
 */
final class PackageName
{
    /** @param non-empty-lowercase-string $packageName */
    private function __construct(public string $packageName)
    {
    }

    /**
     * @throws InvalidPackageName
     *
     * @psalm-pure
     *
     * @psalm-suppress ImpureFunctionCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     * @psalm-suppress ImpureMethodCall - conditional purity {@see https://github.com/azjezz/psl/issues/130}
     */
    public static function fromName(string $name): self
    {
        if (! Regex\matches($name, '{^[a-z0-9](?:[_.-]?[a-z0-9]+)*/[a-z0-9](?:(?:[_.]?|-{0,2})[a-z0-9]+)*$}iD')) {
            throw InvalidPackageName::fromInvalidName($name);
        }

        return new self(Str\lowercase(Type\non_empty_string()->assert($name)));
    }

    /**
     * @throws InvalidPackageName
     *
     * @psalm-pure
     */
    public static function fromReferenceName(string $reference): self
    {
        return self::fromName(Str\replace_every($reference, ['composer://' => '', '\\' => '/']));
    }
}
