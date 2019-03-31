<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

class VersionStability
{
    /** @var string  */
    private $flag;

    /** @var int[]  */
    private $versionNumbers;

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

    /**
     * VersionStability constructor.
     *
     * @param array $stability
     */
    public function __construct(array $version)
    {
        // todo remove trailing zeroes here too
        $this->flag = $version[0] ?? null;
        $this->versionNumbers = isset($version[1]) ? array_map('intval', explode('.', $version[1])) : [];
    }

    public function getVersion(): string
    {
        $version = !empty($this->versionNumbers) ? '.' . join('.',$this->versionNumbers) : null;

        return (string) ($this->flag . $version);
    }

    public function getFlag()
    {
        return $this->flag;
    }

    public function compareFlags(self $other)
    {
        return self::FLAGS_HIERARCHY[$this->flag] <=> self::FLAGS_HIERARCHY[$other->flag];
    }

    public function isGreaterThan(self $other):int
    {
        if($this->getFlag() == null && $other->getFlag() == null) {
            return 0;
        }

        if ($this->getFlag() == null && is_string($other->getFlag())) {
            return 1;
        }

        if (is_string($this->getFlag()) && $other->getFlag() == null) {
            return -1;
        }

        $isGreater = $this->compareFlags($other);

        if ($isGreater != 0) {
            return $isGreater;
        }
        // compare versions here
        foreach (array_keys(array_intersect_key($this->versionNumbers, $other->versionNumbers)) as $index) {
            if ($this->versionNumbers[$index] > $other->versionNumbers[$index]) {
                return 1;
            }

            if ($this->versionNumbers[$index] < $other->versionNumbers[$index]) {
                return -1;
            }
        }

        return count($this->versionNumbers) <=> count($other->versionNumbers);
    }

    public function isEqualTo(self $other) : bool
    {
        // here we assume that if we have no flags at all then stability parts are equal
        if ($this->flag == null && $other->flag == null) {
            return true;
        }

        if ($this->flag == null || $other->flag == null) {
            return false;
        }

        return self::FLAGS_HIERARCHY[$this->flag] == self::FLAGS_HIERARCHY[$other->flag] &&
            $this->versionNumbers === $other->versionNumbers;
    }

}
