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

final class RegExp
{
    // pattern that matches full version only, without boundary sign
    public const TAGGED_VERSION_MATCHER = '\s*(?<version>(?:\d+\.)*\d+)' .
                                                '[._-]?' .
                                                '(?:' .
                                                    '(?<flag>stable|beta|b|rc|alpha|a|patch|p)' .
                                                    '[._-]?' .
                                                    '(?<stability_numbers>(?:\d+\.)*\d+)?' .
                                                ')?\s*';

    private const UNTAGGED_VERSION_MATCHER = '((?:\d+\.)*\d+)' .
                                                '[._-]?' .
                                                '(?:' .
                                                    '(stable|beta|b|rc|alpha|a|patch|p)' .
                                                    '[._-]?' .
                                                    '((?:\d+\.)*\d+)?' .
                                                ')?';

    // pattern that ensures we have a correct boundary in the right place
    public const BOUNDARY_MATCHER = '/^\s*(?<boundary><|<=|=|>=|>)\s*' .
                                    self::TAGGED_VERSION_MATCHER .
                                    '\s*$/';

    public const CLOSED_RANGE_MATCHER = '/^>(=?)\s*' .
                                        self::UNTAGGED_VERSION_MATCHER .
                                        '\s*,\s*<(=?)\s*' .
                                        self::UNTAGGED_VERSION_MATCHER .
                                        '$/';

    public const LEFT_OPEN_RANGE_MATCHER = '/^<(=?)\s*' .
                                            self::UNTAGGED_VERSION_MATCHER .
                                            '$/';

    public const RIGHT_OPEN_RANGE_MATCHER = '/^>(=?)\s*' .
                                            self::UNTAGGED_VERSION_MATCHER .
                                            '$/';
}
