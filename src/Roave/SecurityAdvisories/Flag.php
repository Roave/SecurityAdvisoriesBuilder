<?php
/*
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This software consists of voluntary contributions made by many individuals
 * and is licensed under the MIT license.
 */

declare(strict_types=1);

namespace Roave\SecurityAdvisories;

final class Flag
{
    /**
     * within extent of the same version "patch" flag is of the highest priority
     * e.g. 1.1-alpha < 1.1-beta < 1.1-rc < 1.1-stable < 1.1 < 1.1-p
     */
    private const PRIORITY = [
        'patch'     => 5,
        'p'         => 5,
        ''          => 4, // special case of clean version, e.g. 1.2.3
        'stable'    => 3,
        'rc'        => 2,
        'beta'      => 1,
        'b'         => 1,
        'alpha'     => 0,
        'a'         => 0,
    ];

    private string $literal;

    private function __construct(string $literal)
    {
        $this->literal = $literal;
    }

    public static function build(string $literal) : self
    {
        return new self($literal);
    }

    public function isEqual(Flag $flag) : bool
    {
        return self::PRIORITY[$this->literal] === self::PRIORITY[$flag->literal];
    }

    public function isGreaterThan(Flag $flag) : bool
    {
        return self::PRIORITY[$this->literal] > self::PRIORITY[$flag->literal];
    }

    public function getLiteral() : string
    {
        return $this->literal;
    }
}
