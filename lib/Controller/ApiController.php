<?php
declare(strict_types=1);

namespace OCA\CryptVault\Controller;

use OCA\CryptVault\Service\VaultException;
use OCA\CryptVault\Service\VaultService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\StreamResponse;
use OCP\IRequest;
use OCP\IUserSession;
use OCP\Security\Bruteforce\IThrottler;

class ApiController extends Controller
{
    public function __construct(
        string $appName,
        IRequest $request,
        private IUserSession $userSession,
        private VaultService $vault,
        private ?IThrottler $throttler = null,
    ) {
        parent::__construct($appName, $request);
    }

    private function uid(): string
    {
        $user = $this->userSession->getUser();
        if ($user === null) {
            throw new VaultException('Not logged in', 401);
        }
        return $user->getUID();
    }

    /** @return DataResponse */
    private function err(\Throwable $e): DataResponse
    {
        $code = $e instanceof VaultException ? $e->getHttpCode() : 500;
        // Include the real message so failures are diagnosable from the UI.
        // (No passwords or keys are ever in these messages.)
        return new DataResponse(['error' => $e->getMessage()], $code);
    }

    /**
     * Best-effort brute-force accounting that adapts to the IThrottler
     * signature of the running Nextcloud (2-arg legacy, 3-arg string $ip,
     * or 3-arg array $metadata in newer versions). Never throws.
     */
    private function throttlerCall(string $method, string $action, string $key): void
    {
        if ($this->throttler === null || !method_exists($this->throttler, $method)) {
            return;
        }
        try {
            $params = (new \ReflectionMethod($this->throttler, $method))->getParameters();
            if (count($params) >= 3) {
                $type = $params[2]->getType();
                if ($type instanceof \ReflectionNamedType && $type->getName() === 'array') {
                    $this->throttler->$method($action, $key, ['ip' => $this->request->getRemoteAddress()]);
                } else {
                    $this->throttler->$method($action, $key, $this->request->getRemoteAddress());
                }
            } else {
                $this->throttler->$method($action, $key);
            }
        } catch (\Throwable) {
            // throttling must never break the request
        }
    }

    private function throttlerDelay(string $action, string $key): int
    {
        if ($this->throttler === null || !method_exists($this->throttler, 'getDelay')) {
            return 0;
        }
        try {
            $params = (new \ReflectionMethod($this->throttler, 'getDelay'))->getParameters();
            if (count($params) >= 3) {
                $type = $params[2]->getType();
                if ($type instanceof \ReflectionNamedType && $type->getName() === 'array') {
                    return (int)$this->throttler->getDelay($action, $key, ['ip' => $this->request->getRemoteAddress()]);
                }
                return (int)$this->throttler->getDelay($action, $key, $this->request->getRemoteAddress());
            }
            return (int)$this->throttler->getDelay($action, $key);
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Auth params for service calls: token (fast path) or fileId+password+pim
     * (stateless fallback when the server has no APCu).
     * @return array{string,int,string,int}
     */
    private function auth(): array
    {
        $pw = (string)$this->request->getParam('password', '');
        if ($pw === '') {
            // stateless clients send the password in a header so it stays out
            // of URL query strings (which land in server access logs)
            $pw = (string)$this->request->getHeader('X-CryptVault-Password');
        }
        return [
            (string)$this->request->getParam('token', ''),
            (int)$this->request->getParam('fileId', 0),
            $pw,
            (int)$this->request->getParam('pim', 0),
        ];
    }

    /**
     * Unlock a volume file. Returns a short-lived token (server memory only),
     * or stateless=true when the server has no APCu (client then sends the
     * password with every request).
     */
    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function unlock(int $fileId, string $password, int $pim = 0): DataResponse
    {
        try {
            $uid = $this->uid();
            $key = $uid . '/' . $fileId;
            if ($this->throttlerDelay('cryptvault_unlock', $key) > 0) {
                return new DataResponse(
                    ['error' => 'Too many attempts, try again later'],
                    Http::STATUS_TOO_MANY_REQUESTS
                );
            }
            try {
                $r = $this->vault->unlock($uid, $fileId, $password, $pim);
            } catch (\Throwable $e) {
                if ($e->getHttpCode() === 401) {
                    $this->throttlerCall('throttle', 'cryptvault_unlock', $key);
                }
                throw $e;
            }
            $this->throttlerCall('resetDelay', 'cryptvault_unlock', $key);
            // never echo the password back; wipe local copy
            $password = str_repeat("\0", strlen($password));
            return new DataResponse($r);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function lock(string $token): DataResponse
    {
        try {
            $this->uid();
            $this->vault->lock($token);
            return new DataResponse(['ok' => true]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function list(string $path = '/'): DataResponse
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $entries = $this->vault->listDir($this->uid(), $t, $f, $p, $i, $path);
            return new DataResponse(['entries' => $entries]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function info(string $path = '/'): DataResponse
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            return new DataResponse($this->vault->info($this->uid(), $t, $f, $p, $i, $path));
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function mkdir(string $path): DataResponse
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $this->vault->mkdir($this->uid(), $t, $f, $p, $i, $path);
            return new DataResponse(['ok' => true]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function delete(string $path): DataResponse
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $this->vault->delete($this->uid(), $t, $f, $p, $i, $path);
            return new DataResponse(['ok' => true]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function upload(string $path): DataResponse
    {
        try {
            $uid = $this->uid();
            $file = $this->request->getUploadedFile('file');
            if (!is_array($file) || ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new VaultException('No file uploaded', 400);
            }
            $stream = fopen($file['tmp_name'], 'rb');
            if ($stream === false) {
                throw new VaultException('Cannot read upload', 500);
            }
            try {
                [$t, $f, $p, $i] = $this->auth();
                $this->vault->upload($uid, $t, $f, $p, $i, $path, $stream, (int)$file['size']);
            } finally {
                fclose($stream);
                @unlink($file['tmp_name']);
            }
            return new DataResponse(['ok' => true]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function download(string $path)
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $c = $this->vault->openForDownload($this->uid(), $t, $f, $p, $i, $path);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
        $response = new StreamResponse(function () use ($c, $path) {
            try {
                $c['fs']->readFile($path, function (string $chunk) {
                    echo $chunk;
                });
            } finally {
                $c['vol']->close();
            }
        });
        $response->addHeader('Content-Type', 'application/octet-stream');
        $response->addHeader(
            'Content-Disposition',
            'attachment; filename="' . addcslashes($c['name'], '"\\') . '"'
        );
        $response->addHeader('Content-Length', (string)$c['size']);
        return $response;
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function createVolume(string $name, int $sizeMb, string $password): DataResponse
    {
        try {
            $r = $this->vault->createVolume($this->uid(), $name, $sizeMb, $password);
            $password = str_repeat("\0", strlen($password));
            return new DataResponse($r);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function changePassword(string $newPassword): DataResponse
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $this->vault->changePassword($this->uid(), $t, $f, $p, $i, $newPassword);
            $newPassword = str_repeat("\0", strlen($newPassword));
            return new DataResponse(['ok' => true, 'relock' => true]);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
    }

    /** @NoAdminRequired */
    #[\OCP\AppFramework\Http\Attribute\NoAdminRequired]
    public function headerBackup()
    {
        try {
            [$t, $f, $p, $i] = $this->auth();
            $data = $this->vault->headerBackup($this->uid(), $t, $f, $p, $i);
        } catch (\Throwable $e) {
            return $this->err($e);
        }
        $stream = new StreamResponse(function () use ($data) {
            echo $data;
        });
        $stream->addHeader('Content-Type', 'application/octet-stream');
        $stream->addHeader('Content-Disposition', 'attachment; filename="volume-header-backup.bin"');
        $stream->addHeader('Content-Length', (string)strlen($data));
        return $stream;
    }
}
