<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use Psl;
use Psl\Iter;
use Psl\Regex;
use Psl\Str;

/**
 * A simple version, such as 1.0 or 1.0.0.0 or 2.0.1.3.2
 *
 * @psalm-immutable
 */
final class Boundary
{
    private const VALID_ADJACENCY_MAP = [
        ['<', '='],
        ['<', '>='],
        ['<=', '>'],
        ['=', '>'],
    ];

    private Version $version;

    /** @var string one of "<", "<=", "=", ">=", ">" */
    private string $limitType;

    private function __construct(Version $version, string $limitType)
    {
        $this->version   = $version;
        $this->limitType = $limitType;
    }

    /**
     * @return Boundary
     *
     * @throws Psl\Exception\InvariantViolationException
     */
    public static function fromString(string $boundary): self
    {
        $matches = Regex\first_match($boundary, Matchers::BOUNDARY_MATCHER, Regex\capture_groups(['boundary']));
        Psl\invariant($matches !== null, 'The given string "%s" is not a valid boundary', $boundary);

        $boundary = Str\replace($boundary, $matches['boundary'], '');

        return new self(Version::fromString($boundary), $matches['boundary']);
    }

    public function limitIncluded(): bool
    {
        return Str\Byte\contains($this->limitType, '=');
    }

    public function adjacentTo(self $other): bool
    {
        if (! $other->version->equalTo($this->version)) {
            return false;
        }

        /** @psalm-suppress ImpureFunctionCall this function is operating in a pure manner */
        return Iter\contains(self::VALID_ADJACENCY_MAP, [$this->limitType, $other->limitType])
            || Iter\contains(self::VALID_ADJACENCY_MAP, [$other->limitType, $this->limitType]);
    }

    public function getVersion(): Version
    {
        return $this->version;
    }

    public function getBoundaryString(): string
    {
        return $this->limitType . $this->version->getVersion();
    }
}
