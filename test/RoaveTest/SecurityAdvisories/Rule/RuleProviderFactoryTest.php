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

namespace RoaveTest\SecurityAdvisories\Rule;

use PHPUnit\Framework\TestCase;
use Roave\SecurityAdvisories\Advisory;
use Roave\SecurityAdvisories\Rule\RuleProviderFactory;

use function current;

/**
 * Tests for {@see \Roave\SecurityAdvisories\Rule\RuleProviderFactory}
 *
 * @covers \Roave\SecurityAdvisories\Rule\RuleProviderFactory
 */
final class RuleProviderFactoryTest extends TestCase
{
    public function testProviderProvidesRules(): void
    {
        // Arrange
        $provider = new RuleProviderFactory();

        // Act
        $rules = $provider();

        // Assert
        $this->assertCount(1, $rules);
        $this->assertIsCallable(current($rules));
    }

    public function testProviderProvidesRuleIsApplied(): void
    {
        // Arrange
        $provider = new RuleProviderFactory();

        $config              = [];
        $config['reference'] = 'laminas/laminas-form';
        $config['branches']  = [
            '2.17.x' => [
                'versions' => ['<2.17.2'],
            ],
            '3.0.x' => [
                'versions' => ['>=3','<3.0.2'],
            ],
            '3.1.x' => [
                'versions' => ['>=3.1','<3.1.1'],
            ],
        ];

        $advisory = Advisory::fromArrayData($config);

        // Act
        $rules = $provider();

        // Assert
        $this->assertSame('<2.17.2|>=3,<3.0.2|>=3.1,<3.1.1', $advisory->getConstraint());

        $this->assertCount(1, $rules);
        $rule = current($rules);
        $this->assertIsCallable($rule);

        $advisory = $rule($advisory);
        $this->assertInstanceOf(Advisory::class, $advisory);

        $this->assertSame('<2.17.1|>=3,<3.0.2|>=3.1,<3.1.1', $advisory->getConstraint());
    }

    public function testProviderProvidesRuleNotAppliedBecauseOfPackageName(): void
    {
        // Arrange
        $provider = new RuleProviderFactory();

        $config              = [];
        $config['reference'] = 'laminas/laminas-view';
        $config['branches']  = [
            '2.17.x' => [
                'versions' => ['<2.17.2'],
            ],
        ];

        $advisory = Advisory::fromArrayData($config);

        // Act
        $rules = $provider();

        // Assert
        $this->assertSame('<2.17.2', $advisory->getConstraint());

        $this->assertCount(1, $rules);
        $rule = current($rules);
        $this->assertIsCallable($rule);

        $advisory = $rule($advisory);
        $this->assertInstanceOf(Advisory::class, $advisory);

        $this->assertSame('<2.17.2', $advisory->getConstraint());
    }

    public function testProviderProvidesRuleNotAppliedBecauseOfUnexpectedConstraint(): void
    {
        // Arrange
        $provider = new RuleProviderFactory();

        $config              = [];
        $config['reference'] = 'laminas/laminas-form';
        $config['branches']  = [
            '2.17.x' => [
                'versions' => ['<2.17.2'],
            ],
        ];

        $advisory = Advisory::fromArrayData($config);

        // Act
        $rules = $provider();

        // Assert
        $this->assertSame('<2.17.2', $advisory->getConstraint());

        $this->assertCount(1, $rules);
        $rule = current($rules);
        $this->assertIsCallable($rule);

        $advisory = $rule($advisory);
        $this->assertInstanceOf(Advisory::class, $advisory);

        $this->assertSame('<2.17.2', $advisory->getConstraint());
    }
}
