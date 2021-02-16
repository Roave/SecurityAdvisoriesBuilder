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

namespace RoaveTest\SecurityAdvisories;

use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Exception\InvalidPackageName;
use Roave\SecurityAdvisories\PackageName;

/** @covers \Roave\SecurityAdvisories\PackageName */
final class PackageNameTest extends TestCase
{
    /** @dataProvider validPackageNames */
    public function testStoresValidPackageName(string $name): void
    {
        self::assertSame($name, PackageName::fromName($name)->packageName);
    }

    /** @return non-empty-list<array{string}> */
    public function validPackageNames(): array
    {
        return [
            ['foo/bar'],
            ['a/b'],
            ['1/2'],
            ['a-b/c-d'],
            ['a_b/c_d'],
        ];
    }

    /** @dataProvider invalidPackageNames */
    public function testWillRejectInvalidPackageName(string $invalidName): void
    {
        $this->expectException(InvalidPackageName::class);

        PackageName::fromName($invalidName);
    }

    /** @return non-empty-list<array{string}> */
    public function invalidPackageNames(): array
    {
        return [
            [''],
            ['foo'],
            ['adminer'],
            ['foo.bar'],
            ['foo bar'],
            ['-ab/-cd'],
            ['_ab/_cd'],
            ['foo bar'],
            ['foo /bar'],
            ['foo/ bar'],
        ];
    }
}
