<?php

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

// value object
use Psl\Type;

final class Source
{
    /** @var non-empty-string $summary */
    public string $summary;

    /** @var non-empty-string $uri */
    public string $uri;

    /**
     * @param non-empty-string $summary
     * @param non-empty-string $uri
     */
    private function __construct(string $summary, string $uri)
    {
        $this->summary = $summary;
        $this->uri     = $uri;
    }

    public static function new(string $summary, string $uri): self
    {
        return new self(Type\non_empty_string()->assert($summary), Type\non_empty_string()->assert($uri));
    }
}
