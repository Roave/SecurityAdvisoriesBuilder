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

use ErrorException;
use Psl\Filesystem;
use Psl\Json;
use Psl\Shell;
use Psl\Str;

// Note: this script is responsible for handling incoming requests from the github push notifications,
// and to re-run the code generation/checks every time
(static function () {
    set_error_handler(
        static function ($errorCode, $message = '', $file = '', $line = 0) {
            throw new ErrorException($message, 0, $errorCode, $file, $line);
        },
        E_STRICT | E_NOTICE | E_WARNING
    );

    $getCurrentSha1 = static function (string $directory): string {
        return Str\trim(Shell\execute('git', ['rev-parse', '--verify', 'HEAD'], $directory));
    };

    (static function () {
        require __DIR__ . '/build-conflicts.php';
    })();

    $previousSha1 = $getCurrentSha1((string)Filesystem\canonicalize(__DIR__ . '/build/roave-security-advisories-original'));
    $newSha1 = $getCurrentSha1((string)Filesystem\canonicalize(__DIR__ . '/build/roave-security-advisories'));

    Shell\execute('git', ['push', 'origin', 'master'], (string)Filesystem\canonicalize(__DIR__ . '/build/roave-security-advisories'));

    header('Content-Type: application/json');
    echo Json\encode([
        'before' => $previousSha1,
        'after' => $newSha1,
    ]);
})();
