<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use function assert;
use function in_array;
use function is_string;
use function Safe\preg_match;
use function Safe\sprintf;
use function str_replace;
use function strpos;

/**
 * A simple version, such as 1.0 or 1.0.0.0 or 2.0.1.3.2
 */
final class Boundary
{
    private const IN_ARRAY_STRICT = true;

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
     * @throws InvalidArgumentException
     */
    public static function fromString(string $boundary) : self
    {
        if (preg_match(Matchers::BOUNDARY_MATCHER, $boundary, $matches) !== 1) {
            throw new InvalidArgumentException(sprintf('The given string "%s" is not a valid boundary', $boundary));
        }

        assert(isset($matches['boundary']));
        assert(is_string($matches['boundary']));

        $boundary = str_replace($matches['boundary'], '', $boundary);

        return new self(
            Version::fromString($boundary),
            $matches['boundary']
        );
    }

    public function limitIncluded() : bool
    {
        return strpos($this->limitType, '=') !== false;
    }

    public function adjacentTo(self $other) : bool
    {
        if (! $other->version->equalTo($this->version)) {
            return false;
        }

        return in_array([$this->limitType, $other->limitType], self::VALID_ADJACENCY_MAP, self::IN_ARRAY_STRICT)
            || in_array([$other->limitType, $this->limitType], self::VALID_ADJACENCY_MAP, self::IN_ARRAY_STRICT);
    }

    public function getVersion() : Version
    {
        return $this->version;
    }

    public function getBoundaryString() : string
    {
        return $this->limitType . $this->version->getVersion();
    }
}
