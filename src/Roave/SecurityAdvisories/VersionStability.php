<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

class VersionStability
{
    /** @var string  */
    private $flag;

    /** @var int[]  */
    private $version;

    private const FLAGS_HIERARCHY = [
        'stable'    => 4,
        'rc'        => 3,
        'beta'      => 2,
        'b'         => 2,
        'alpha'     => 1,
        'a'         => 1,
        'patch'     => 0,
        'p'         => 0,
    ];

    public function __construct(array $stability)
    {
        $this->flag = $stability[0];

        // todo remove trailing zeroes here too
        $this->version = !empty($stability[1]) ? array_map('intval', explode('.', $stability[1])) : [];
    }

    public function getVersion()
    {
        $version = !empty($this->version) ? '.' . join('.',$this->version) : null;

        return $this->flag . $version;
    }

    public function getFlag()
    {
        return $this->flag;
    }

    public function compareFlags(self $other)
    {
        return self::FLAGS_HIERARCHY[$this->flag] <=> self::FLAGS_HIERARCHY[$other->flag];
    }

}
