<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

class VersionStability
{
    /** @var string  */
    private $flag;

    /** @var int[]  */
    private $version;

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

}
