<?php

namespace Roave\SecurityAdvisories;

// value object
final class Source
{
    public string $summary;
    public string $uri;

    private function __construct( string $summary , string $uri)
    {
        $this->summary = $summary;
        $this->uri = $uri;
    }

    public static function New(string $summary, string $uri): self
    {
        return new self($summary, $uri);
    }
}



