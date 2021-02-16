<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories\Exception;

use InvalidArgumentException;

use function sprintf;

final class InvalidPackageName extends InvalidArgumentException
{
    public static function fromInvalidName(string $invalidName): self
    {
        return new self(sprintf('Package "%s" has invalid name', $invalidName));
    }
}
