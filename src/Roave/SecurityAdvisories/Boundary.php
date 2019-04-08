<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

use InvalidArgumentException;
use function in_array;
use function preg_replace;
use function Safe\preg_match;
use function Safe\sprintf;
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

    /** @var Version */
    private $version;

    /** @var string one of "<", "<=", "=", ">=", ">" */
    private $limitType;

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
    public static function fromString(string $boundaryVersion) : self
    {
        if (preg_match(RegExp::BOUNDARY_MATCHER, $boundaryVersion, $matches) !== 1) {
            throw new InvalidArgumentException(sprintf('The given string "%s" is not a valid boundary', $boundaryVersion));
        }

        $boundaryVersion = preg_replace('/' . $matches['boundary'] . '/', '', $boundaryVersion);

        return new self(
            Version::fromString($boundaryVersion),
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
