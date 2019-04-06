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

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Version;
use function array_map;
use function Safe\array_combine;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Version}
 *
 * @covers \Roave\SecurityAdvisories\Version
 */
final class VersionTest extends TestCase
{
    /**
     * @dataProvider invalidVersionStringsProvider
     */
    public function testVersionWillNotAllowInvalidFormats(string $versionString) : void
    {
        $this->expectException(InvalidArgumentException::class);

        Version::fromString($versionString);
    }

    /**
     * @dataProvider validVersionStringProvider
     */
    public function testGetVersionWithValidVersion(string $versionString, string $normalisedExpectation) : void
    {
        self::assertSame($normalisedExpectation, Version::fromString($versionString)->getVersion());
    }

    /**
     * @dataProvider greaterThanComparisonVersionsProvider
     */
    public function testGreaterThanVersionWith(
        string $version1String,
        string $version2String,
        bool $v1GreaterThanV2,
        bool $v2GreaterThanV1
    ) : void {
        $version1 = Version::fromString($version1String);
        $version2 = Version::fromString($version2String);

        self::assertSame($v1GreaterThanV2, $version1->isGreaterThan($version2));
        self::assertSame($v2GreaterThanV1, $version2->isGreaterThan($version1));
    }

    /**
     * @dataProvider greaterOrEqualThanComparisonVersionsProvider
     */
    public function testGreaterOrEqualThanVersionWith(
        string $version1String,
        string $version2String,
        bool $v1GreaterOrEqualThanV2,
        bool $v2GreaterOrEqualThanV1
    ) : void {
        $version1 = Version::fromString($version1String);
        $version2 = Version::fromString($version2String);

        self::assertSame($v1GreaterOrEqualThanV2, $version1->isGreaterOrEqualThan($version2));
        self::assertSame($v2GreaterOrEqualThanV1, $version2->isGreaterOrEqualThan($version1));
    }

    /**
     * @dataProvider equivalentVersionProvider
     */
    public function testVersionEquivalence(string $version1String, string $version2String) : void
    {
        $version1 = Version::fromString($version1String);
        $version2 = Version::fromString($version2String);

        self::assertEquals($version1, $version2);
        self::assertTrue($version1->equalTo($version2));
        self::assertTrue($version2->equalTo($version1));
    }

    /**
     * @dataProvider nonEquivalentVersionProvider
     */
    public function testVersionNonEquivalence(string $version1String, string $version2String) : void
    {
        $version1 = Version::fromString($version1String);
        $version2 = Version::fromString($version2String);

        self::assertNotEquals($version1, $version2);
        self::assertFalse($version1->equalTo($version2));
        self::assertFalse($version2->equalTo($version1));
    }

    /**
     * @return string[][]
     */
    public function validVersionStringProvider() : array
    {
        return [
            ['0', '0'],
            ['0.0', '0'],
            ['1', '1'],
            ['12345', '12345'],
            ['12345.00', '12345'],
            ['0.1.2.3.4', '0.1.2.3.4'],
            ['1.2.3.4', '1.2.3.4'],
            ['1.2.3.4.5.6.7.8.9.10', '1.2.3.4.5.6.7.8.9.10'],
            ['12345.12345.12345.12345.0', '12345.12345.12345.12345'],
            ['1-STABLE', '1-stable'], // uppercase test
            ['1.b', '1-b'], // check dot in front of stability
            ['1_beta', '1-beta'], // check underscore in front of stability
            ['1-stable', '1-stable'],
            ['1-beta', '1-beta'],
            ['1-rc', '1-rc'],
            ['1-alpha', '1-alpha'],
            ['1-a', '1-a'],
            ['1-patch', '1-patch'],
            ['1-p', '1-p'],
            ['1.0.0-alpha', '1-alpha'],
            ['1.0.0-alpha1', '1-alpha.1'],
            ['1.0.0-alpha.1.2.3.0.0.0', '1-alpha.1.2.3'],
            ['1-beta6_bugfix', '1-beta.6'],
            ['1-beta_6+feature1', '1-beta.6'],
            ['1-beta.6.6+feature2.9.0', '1-beta.6.6'],
            ['1-beta.6.6.0+meta.9.0', '1-beta.6.6'],
            // todo: also valid versions we do not handle for now
//            ['1.0.0-alpha.beta.1'],
//            ['1.0.0-alpha.beta.1.2+preview1'],
//            ['1.0.0-0.3.7'],
//            ['1.0.0-x.7.z.92'],
            // todo: find and implement more exotic versions ?
        ];
    }

    /**
     * @return string[][]|bool[][]
     */
    public function greaterThanComparisonVersionsProvider() : array
    {

        $versions = [
            ['0', '0', false, false],
            ['1', '1', false, false],
            ['3', '3', false, false],
            ['100', '99', true, false],
            ['1', '0', true, false],
            ['1.1', '1.1', false, false],
            ['1.10', '1.1', true, false],
            ['1.100', '1.100', false, false],
            ['1.2', '1.100', false, true],
            ['1.1', '1.1.0', false, false],
            ['1.1', '1.1.0.0', false, false],
            ['1.1', '1.1.0.0.1', false, true],
            ['1.0.0.0.0.0.2', '1.0.0.0.0.2', false, true],
            ['1.0.12', '1.0.11', true, false],
            // stability vs simple versions
            ['1-stable', '1', false, true],
            ['1-rc', '1', false, true],
            ['1-beta', '1', false, true],
            ['1-b', '1', false, true],
            ['1-alpha', '1', false, true],
            ['1-a', '1', false, true],
            ['1-patch', '1', false, true],
            ['1-p', '1', false, true],
            // stabilities vs stabilities
            ['1-stable', '1-rc', true, false],
            ['1-rc', '1-beta', true, false],
            ['1-beta', '1-alpha', true, false],
            ['1-b', '1-alpha', true, false],
            ['1-alpha', '1-patch', true, false],
            ['1-a', '1-patch', true, false],
            ['1-patch', '1', false, true],
            ['1-p', '1', false, true],
            // more complex comparisons
            ['1-stable.1', '1-stable.1', false, false],
            ['1-stable.1.2', '1-stable.1', true, false],
            ['1-stable.1.2.3', '1-stable.1.2', true, false],
            ['1-stable.1.2.3.4.5.6.7.8', '1-stable.1.2.3.4.5.6.7', true, false],
            // equal examples
            ['1-stable', '1-stable', false, false],
            ['1-rc', '1-rc', false, false],
            ['1-beta', '1-beta', false, false],
            ['1-b', '1-b', false, false],
            ['1-alpha', '1-alpha', false, false],
            ['1-a', '1-a', false, false],
            ['1-patch', '1-patch', false, false],
            ['1-p', '1-p', false, false],
            ['1-stable.1.1.1.1', '1-stable.1.1.1.1', false, false],
            // 0 strip check
            ['1-stable.1.1.1.1', '1-stable.1.1.1.1.0', false, false],
        ];

        return array_combine(
            array_map(
                static function (array $versionData) {
                    return $versionData[0] . ' > ' . $versionData[1];
                },
                $versions
            ),
            $versions
        );
    }

    /**
     * @return string[][]|bool[][]
     */
    public function greaterOrEqualThanComparisonVersionsProvider() : array
    {
        $versions = [
            ['0', '0', true, true],
            ['0.0', '0', true, true],
            ['0.0.0', '0', true, true],
            ['0.0.0.1', '0', true, false],
            ['100', '99', true, false],
            ['1', '0', true, false],
            ['1.1', '1.1', true, true],
            ['1.10', '1.1', true, false],
            ['1.10', '1.10', true, true],
            ['1.100', '1.100', true, true],
            ['1.2', '1.100', false, true],
            ['1.1', '1.1.0', true, true],
            ['1.1', '1.1.0.0', true, true],
            ['1.1', '1.1.0.0.1', false, true],
            ['1.0.0.0.0.0.2', '1.0.0.0.0.2', false, true],
            ['1.0.12', '1.0.11', true, false],
            // stability vs simple versions
            ['1-stable', '1', false, true],
            ['1-rc', '1', false, true],
            ['1-beta', '1', false, true],
            ['1-b', '1', false, true],
            ['1-alpha', '1', false, true],
            ['1-a', '1', false, true],
            ['1-patch', '1', false, true],
            ['1-p', '1', false, true],
            // stabilities vs stabilities
            ['1-stable', '1-rc', true, false],
            ['1-rc', '1-beta', true, false],
            ['1-beta', '1-alpha', true, false],
            ['1-b', '1-alpha', true, false],
            ['1-alpha', '1-patch', true, false],
            ['1-a', '1-patch', true, false],
            ['1-patch', '1', false, true],
            ['1-p', '1', false, true],
            // more complex comparisons
            ['1-stable.1', '1-stable.1', true, true],
            ['1-stable.1.2', '1-stable.1', true, false],
            ['1-stable.1.2.3', '1-stable.1.2', true, false],
            ['1-stable.1.2.3.4.5.6.7.8', '1-stable.1.2.3.4.5.6.7', true, false],
            ['2.1.0-beta1', '2.1', false, true],
            // equal examples
            ['1-stable', '1-stable', true, true],
            ['1-rc', '1-rc', true, true],
            ['1-beta', '1-beta', true, true],
            ['1-b', '1-b', true, true],
            ['1-alpha', '1-alpha', true, true],
            ['1-a', '1-a', true, true],
            ['1-patch', '1-patch', true, true],
            ['1-p', '1-p', true, true],
            ['1-stable.1.1.1.1', '1-stable.1.1.1.1', true, true],
            // 0 strip check
            ['1-stable.1.1.1.1', '1-stable.1.1.1.1.0', true, true],
        ];

        return array_combine(
            array_map(
                static function (array $versionData) {
                    return $versionData[0] . ' >= ' . $versionData[1];
                },
                $versions
            ),
            $versions
        );
    }

    /**
     * @return string[][]
     */
    public function invalidVersionStringsProvider() : array
    {
        return [
            [''],
            ['alpha'],
            ['beta'],
            ['.1'],
//            ['1.2.3-alpha.beta'], // it is actually a legit version, we just do not handle it for now
//            ['4.5.6-8.9']
    ];
    }

    /**
     * @return string[][]
     */
    public function equivalentVersionProvider() : array
    {
        return [
            ['0', '0.0'],
            ['1', '1.0'],
            ['1', '1.0.0'],
            ['1.0.0.0', '1.0.0'],
            ['2.0.1.0', '2.0.1'],
            ['2.0.1.0.0.0', '2.0.1'],
            ['0.0.0-beta1', '0-beta1']
        ];
    }

    /**
     * @return string[][]
     */
    public function nonEquivalentVersionProvider() : array
    {
        return [
            ['0.1', '0.0'],
            ['1.0.1', '1.0'],
            ['1', '1.0.2'],
            ['1.0.0.1', '1.0.0'],
            ['2.0.1.1', '2.0.1'],
            ['2.0.1.0.0.0', '2.0.2'],
            ['0.1-patch-3.4', '0.0-patch-3.4'],
            ['1.0.1-patch-3.4', '1.0-patch-3.4'],
            ['1-patch-3.4', '1.0.2-patch-3.4'],
            ['1.0.0.1-patch-3.4', '1.0.0-patch-3.4'],
            ['2.0.1.1-patch-3.4', '2.0.1-patch-3.4'],
            ['2.0.1.0.0.0-patch-3.4', '2.0.2-patch-3.4'],
            ['1-rc', '1-stable'],
            ['1-stable', '1-beta'],
            ['1-beta', '1-b.1'],
            ['1-b', '1-alpha'],
            ['1-alpha', '1-a.1'],
            ['1-a.1', '1-patch'],
            ['1-patch', '1-p.1'],
            ['1-alpha.1', '1-alpha.1.2'],
            ['1-alpha.1.2', '1-alpha.1'],
            ['1-alpha.1.2.3.4.5', '1-alpha.1'],
        ];
    }
}
