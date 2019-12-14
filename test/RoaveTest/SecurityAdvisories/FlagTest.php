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
use Roave\SecurityAdvisories\Flag;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Flag}
 *
 * @covers \Roave\SecurityAdvisories\Flag
 */
final class FlagTest extends TestCase
{
    /**
     * @dataProvider isGreaterFlagDataProvider
     */
    public function testFlagIsGreaterThanOther(
        ?string $firstFlag,
        ?string $otherFlag,
        bool $firstExpected,
        bool $secondExpected
    ) : void {
        $first  = Flag::build($firstFlag);
        $second = Flag::build($otherFlag);

        self::assertEquals($firstExpected, $first->isGreaterThan($second));
        self::assertEquals($secondExpected, $second->isGreaterThan($first));
    }

    /**
     * @dataProvider isEqualDataProvider
     */
    public function testFlagIsEqualThanOther(
        ?string $firstFlag,
        ?string $otherFlag,
        bool $firstExpected,
        bool $secondExpected
    ) : void {
        $first  = Flag::build($firstFlag);
        $second = Flag::build($otherFlag);

        self::assertEquals($firstExpected, $first->isEqual($second));
        self::assertEquals($secondExpected, $second->isEqual($first));
    }

    /**
     * @dataProvider getterTestDataProvider
     */
    public function testThatGetterWorks(
        ?string $literal,
        ?string $expected
    ) : void {
        $flag = Flag::build($literal);

        self::assertSame($expected, $flag->getLiteral());
    }

    /**
     * @return mixed[]
     */
    public function isGreaterFlagDataProvider() : array
    {
        return [
            ['patch', 'p', false, false],
            ['patch', null, true, false],
            ['patch', 'stable', true, false],
            ['patch', 'rc', true, false],
            ['patch', 'beta', true, false],
            ['patch', 'b', true, false],
            ['patch', 'alpha', true, false],
            ['patch', 'a', true, false],

            ['p', null, true, false],
            ['p', 'stable', true, false],
            ['p', 'rc', true, false],
            ['p', 'beta', true, false],
            ['p', 'b', true, false],
            ['p', 'alpha', true, false],
            ['p', 'a', true, false],

            [null, 'stable', true, false],
            [null, 'rc', true, false],
            [null, 'beta', true, false],
            [null, 'b', true, false],
            [null, 'alpha', true, false],
            [null, 'a', true, false],

            ['stable', 'rc', true, false],
            ['stable', 'beta', true, false],
            ['stable', 'b', true, false],
            ['stable', 'alpha', true, false],
            ['stable', 'a', true, false],

            ['rc', 'beta', true, false],
            ['rc', 'b', true, false],
            ['rc', 'alpha', true, false],
            ['rc', 'a', true, false],

            ['beta', 'b', false, false],
            ['beta', 'alpha', true, false],
            ['beta', 'a', true, false],

            ['b', 'alpha', true, false],
            ['b', 'a', true, false],

            ['alpha', 'a', false, false],

        ];
    }

    /**
     * @return mixed[]
     */
    public function isEqualDataProvider() : array
    {
        return [
            ['patch', 'p', true, true],
            ['beta', 'b', true, true],
            ['alpha', 'a', true, true],
            [null, null, true, true],
        ];
    }

    /**
     * @return mixed[]
     */
    public function getterTestDataProvider() : array
    {
        return [
            ['patch', 'patch'],
            ['p', 'p'],
            [null, null],
            ['stable', 'stable'],
            ['rc', 'rc'],
            ['beta', 'beta'],
            ['b', 'b'],
            ['alpha', 'alpha'],
            ['a', 'a'],
        ];
    }
}
