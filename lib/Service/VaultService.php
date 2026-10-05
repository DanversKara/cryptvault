<?php
declare(strict_types=1);

namespace OCA\CryptVault\Service;

use OCA\CryptVault\Crypto\VeraCryptVolume;
use OCA\CryptVault\Crypto\VolumeException;
use OCA\CryptVault\Fs\ExFatVolume;
use OCA\CryptVault\Fs\FatVolume;
use OCP\Files\IRootFolder;
use OCP\Files\Node;
use Psr\Log\LoggerInterface;

/**
 * Opens VeraCrypt volumes stored as Nextcloud files and hands out short-lived
 * access tokens. The volume password is NEVER stored: on unlock the header key
 * is derived (slow PBKDF2) and kept in server memory (APCu, never disk) under
 * a random token. Follow-up requests present the token; the header key is
 * re-used to skip PBKDF2. The browser keeps the token in memory only.
 */
class VaultService
{
    private const TOKEN_TTL = 1800; // 30 minutes, sliding
    private const MAX_UPLOAD = 2 * 1024 * 1024 * 1024; // 2 GiB per file

    public function __construct(
        private IRootFolder $rootFolder,
        private LoggerInterface $logger,
    ) {
    }

    // ---------- token / cache ----------

    private static function cacheAvailable(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    /** @return array{uid:string,fileId:int,key:string,offset:int,fs:string}|null */
    private function tokenGet(string $token): ?array
    {
        if (!self::cacheAvailable() || !preg_match('/^[0-9a-f]{64}$/', $token)) {
            return null;
        }
        $v = apcu_fetch('cryptvault_' . $token, $ok);
        if (!$ok || !is_array($v)) {
            return null;
        }
        // slide the TTL
        apcu_store('cryptvault_' . $token, $v, self::TOKEN_TTL);
        return $v;
    }

    private function tokenPut(string $token, array $v): void
    {
        apcu_store('cryptvault_' . $token, $v, self::TOKEN_TTL);
    }

    private function tokenDelete(string $token): void
    {
        if (self::cacheAvailable() && preg_match('/^[0-9a-f]{64}$/', $token)) {
            // best-effort wipe before delete
            apcu_store('cryptvault_' . $token, str_repeat("\0", 128), 1);
            apcu_delete('cryptvault_' . $token);
        }
    }

    /** Simple APCu mutex around mutating ops on one volume file. */
    private function withLock(int $fileId, callable $fn)
    {
        $key = 'cryptvault_lock_' . $fileId;
        if (!self::cacheAvailable()) {
            return $fn();
        }
        $deadline = microtime(true) + 30;
        while (!apcu_add($key, 1, 35)) {
            if (microtime(true) > $deadline) {
                throw new VaultException('Volume is busy, try again');
            }
            usleep(50000);
        }
        try {
            return $fn();
        } finally {
            apcu_delete($key);
        }
    }

    // ---------- node resolution ----------

    /**
     * Resolve a file id to a Node the user may access. Throws VaultException
     * when the file does not exist, is not theirs, or is not a regular file.
     */
    public function getNode(string $uid, int $fileId): Node
    {
        $userFolder = $this->rootFolder->getUserFolder($uid);
        $nodes = $userFolder->getById($fileId);
        if (count($nodes) === 0) {
            throw new VaultException('Volume file not found', 404);
        }
        $node = $nodes[0];
        if ($node->getType() !== \OCP\Files\FileInfo::TYPE_FILE) {
            throw new VaultException('Not a file', 400);
        }
        if (!$node->isUpdateable()) {
            // read-only is fine for browsing; writes will fail later with 403
        }
        return $node;
    }

    /**
     * Get a local filesystem path for the node. The volume file must live
     * on real local storage: with object storage (S3 etc.) getLocalFile()
     * would hand us a throwaway temp copy and writes would be silently
     * lost, so we refuse that case with a clear error instead.
     */
    public function getLocalPath(Node $node): string
    {
        $storage = $node->getStorage();
        if ($storage === null) {
            throw new VaultException('No storage for volume file', 500);
        }
        try {
            $inner = $storage;
            while (is_object($inner)
                && class_exists('OC\Files\Storage\Wrapper\Wrapper')
                && $inner instanceof \OC\Files\Storage\Wrapper\Wrapper) {
                $inner = $inner->getWrappedStorage();
            }
            if (class_exists('OC\Files\Storage\Local')
                && !($inner instanceof \OC\Files\Storage\Local)) {
                throw new VaultException(
                    'Volume must live on local disk storage (object storage like S3 is not supported)', 400);
            }
        } catch (VaultException $e) {
            throw $e;
        } catch (\Throwable) {
            // storage introspection unavailable; fall through to path check
        }
        // \OC\Files\Storage\Local or wrappers around it
        $local = $storage->getLocalFile($node->getInternalPath());
        if (!is_string($local) || !is_file($local)) {
            throw new VaultException('Volume must live on local storage', 400);
        }
        return $local;
    }

    // ---------- unlock / lock ----------

    /**
     * @return array{token:string,fs:string,free:int,size:int}
     * @throws VaultException
     */
    public function unlock(string $uid, int $fileId, string $password, int $pim = 0): array
    {
        if ($password === '') {
            throw new VaultException('Empty password', 400);
        }
        if ($pim < 0 || $pim > 999999) {
            throw new VaultException('Bad PIM', 400);
        }
        $node = $this->getNode($uid, $fileId);
        $name = $node->getName();
        if (!preg_match('/\.hc$/i', $name) && !preg_match('/\.tc$/i', $name)) {
            throw new VaultException('Not a volume file (.hc/.tc)', 400);
        }
        $local = $this->getLocalPath($node);
        try {
            $vol = VeraCryptVolume::open($local, $password, $pim);
        } catch (VolumeException $e) {
            throw new VaultException('Wrong password, or this volume uses settings CryptVault cannot open.', 401);
        }
        try {
            $fs = $this->detectFs($vol);
            $token = bin2hex(random_bytes(32));
            $entry = [
                'uid' => $uid,
                'fileId' => $fileId,
                'key' => $vol->getHeaderKey(),
                'offset' => $vol->getHeaderOffset(),
                'fs' => $fs['type'],
            ];
            if (self::cacheAvailable()) {
                $this->tokenPut($token, $entry);
            } else {
                // No memory cache: token is unusable; caller must send the
                // password with every request (stateless fallback).
                $token = '';
            }
            return [
                'token' => $token,
                'stateless' => $token === '',
                'fs' => $fs['type'],
                'fsLabel' => $fs['label'],
                'free' => $fs['free'],
                'size' => $vol->getVolumeSize(),
                'fileName' => $name,
            ];
        } finally {
            $vol->close();
        }
    }

    public function lock(string $token): void
    {
        $this->tokenDelete($token);
    }

    /**
     * Open a session either via token (fast, cached key) or statelessly via
     * password (slow PBKDF2, used when APCu is unavailable).
     * The returned context owns an open volume; pass it to doWithSession().
     * @return array{vol:VeraCryptVolume,fs:FatVolume|ExFatVolume,node:Node,fileId:int,token:string}
     */
    private function openSession(string $uid, string $token, int $fileId, string $password, int $pim): array
    {
        if ($token !== '') {
            $c = $this->openForToken($uid, $token);
            return [
                'vol' => $c['vol'], 'fs' => $c['fs'], 'node' => $c['node'],
                'fileId' => $c['entry']['fileId'], 'token' => $token,
            ];
        }
        $c = $this->openWithPassword($uid, $fileId, $password, $pim);
        return [
            'vol' => $c['vol'], 'fs' => $c['fs'], 'node' => $c['node'],
            'fileId' => $fileId, 'token' => '',
        ];
    }

    /** Run $fn with an open session, always closing the volume afterwards. */
    private function doWithSession(string $uid, string $token, int $fileId, string $password, int $pim, callable $fn)
    {
        $c = $this->openSession($uid, $token, $fileId, $password, $pim);
        try {
            return $fn($c);
        } finally {
            $c['vol']->close();
        }
    }

    /**
     * Open the volume for a token (fast path: cached header key, no PBKDF2).
     * @return array{vol:VeraCryptVolume,fs:FatVolume|ExFatVolume,node:Node,entry:array}
     * @throws VaultException
     */
    public function openForToken(string $uid, string $token): array
    {
        $entry = $this->tokenGet($token);
        if ($entry === null || $entry['uid'] !== $uid) {
            throw new VaultException('Not unlocked (or session expired)', 401);
        }
        $node = $this->getNode($uid, $entry['fileId']);
        $local = $this->getLocalPath($node);
        try {
            $vol = VeraCryptVolume::openWithHeaderKey($local, $entry['key'], $entry['offset']);
        } catch (VolumeException $e) {
            $this->tokenDelete($token);
            throw new VaultException('Volume changed, please unlock again', 401);
        }
        $fs = $entry['fs'] === 'exfat' ? new ExFatVolume($vol) : new FatVolume($vol);
        return ['vol' => $vol, 'fs' => $fs, 'node' => $node, 'entry' => $entry];
    }

    /**
     * Stateless fallback: open with password on every request (no APCu).
     * @return array{vol:VeraCryptVolume,fs:FatVolume|ExFatVolume,node:Node}
     */
    public function openWithPassword(string $uid, int $fileId, string $password, int $pim = 0): array
    {
        $node = $this->getNode($uid, $fileId);
        $local = $this->getLocalPath($node);
        try {
            $vol = VeraCryptVolume::open($local, $password, $pim);
        } catch (VolumeException $e) {
            throw new VaultException('Wrong password', 401);
        }
        $info = $this->detectFs($vol);
        $fs = $info['type'] === 'exfat' ? new ExFatVolume($vol) : new FatVolume($vol);
        return ['vol' => $vol, 'fs' => $fs, 'node' => $node];
    }

    /** @return array{type:string,label:string,free:int} */
    private function detectFs(VeraCryptVolume $vol): array
    {
        try {
            $fat = new FatVolume($vol);
            $t = $fat->getFatType();
            return ['type' => 'fat', 'label' => 'FAT' . $t, 'free' => $fat->freeSpace()];
        } catch (VolumeException) {
        }
        try {
            new ExFatVolume($vol);
            return ['type' => 'exfat', 'label' => 'exFAT', 'free' => -1];
        } catch (VolumeException) {
        }
        throw new VaultException('No supported filesystem found in volume (need FAT or exFAT)', 400);
    }

    // ---------- filesystem operations ----------

    /** @return list<array{name:string,type:string,size:int,mtime:int}> */
    public function listDir(string $uid, string $token, int $fileId, string $password, int $pim, string $path): array
    {
        return $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($path) {
            $this->assertSafePath($path);
            $out = [];
            try {
                $entries = $c['fs']->listDir($path === '' ? '/' : $path);
            } catch (VolumeException $e) {
                throw new VaultException($e->getMessage(), 400);
            }
            foreach ($entries as $e) {
                $out[] = [
                    'name' => $e['name'],
                    'type' => $e['isDir'] ? 'dir' : 'file',
                    'size' => $e['isDir'] ? 0 : $e['size'],
                    'mtime' => $e['mtime'],
                ];
            }
            usort($out, fn($a, $b) => [$b['type'] === 'dir', $a['name']] <=> [$a['type'] === 'dir', $b['name']]);
            return $out;
        });
    }

    public function mkdir(string $uid, string $token, int $fileId, string $password, int $pim, string $path): void
    {
        $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($path) {
            $this->assertUpdateable($c['node']);
            $this->assertSafePath($path);
            $this->withLock($c['fileId'], function () use ($c, $path) {
                try {
                    $c['fs']->mkdir($path);
                } catch (VolumeException $e) {
                    throw new VaultException($e->getMessage(), 400);
                }
            });
            $c['node']->touch();
        });
    }

    public function delete(string $uid, string $token, int $fileId, string $password, int $pim, string $path): void
    {
        $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($path) {
            $this->assertUpdateable($c['node']);
            $this->assertSafePath($path);
            if ($path === '' || $path === '/') {
                throw new VaultException('Refusing to delete volume root', 400);
            }
            $this->withLock($c['fileId'], function () use ($c, $path) {
                try {
                    $c['fs']->delete($path);
                } catch (VolumeException $e) {
                    throw new VaultException($e->getMessage(), 400);
                }
            });
            $c['node']->touch();
        });
    }

    /**
     * Write an uploaded file into the volume. $stream is a readable PHP stream.
     */
    public function upload(string $uid, string $token, int $fileId, string $password, int $pim, string $path, $stream, int $size): void
    {
        if ($size < 0 || $size > self::MAX_UPLOAD) {
            throw new VaultException('File too large', 400);
        }
        $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($path, $stream) {
            $this->assertUpdateable($c['node']);
            $this->assertSafePath($path);
            $this->withLock($c['fileId'], function () use ($c, $path, $stream) {
                try {
                    $c['fs']->writeFile($path, $stream);
                } catch (VolumeException $e) {
                    throw new VaultException($e->getMessage(), 400);
                }
            });
            $c['node']->touch();
        });
    }

    /**
     * Open a volume for streaming download. The caller owns the returned
     * volume and MUST call $vol->close() when done (even on error).
     * @return array{vol:VeraCryptVolume,fs:FatVolume|ExFatVolume,node:Node,name:string,size:int,mtime:int}
     */
    public function openForDownload(string $uid, string $token, int $fileId, string $password, int $pim, string $path): array
    {
        $c = $this->openSession($uid, $token, $fileId, $password, $pim);
        try {
            $this->assertSafePath($path);
            try {
                $st = $c['fs']->stat($path);
            } catch (VolumeException $e) {
                throw new VaultException($e->getMessage(), 404);
            }
            if ($st['isDir']) {
                throw new VaultException('Cannot download a folder', 400);
            }
            $c['name'] = basename($path);
            $c['size'] = $st['size'];
            $c['mtime'] = $st['mtime'];
            // NOTE: vol left open for the caller to stream then close.
            return $c;
        } catch (\Throwable $e) {
            $c['vol']->close();
            throw $e;
        }
    }

    /** @return array{type:string,size:int,mtime:int} */
    public function info(string $uid, string $token, int $fileId, string $password, int $pim, string $path): array
    {
        return $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($path) {
            $this->assertSafePath($path);
            try {
                $st = $c['fs']->stat($path);
            } catch (VolumeException $e) {
                throw new VaultException($e->getMessage(), 404);
            }
            return [
                'type' => $st['isDir'] ? 'dir' : 'file',
                'size' => $st['size'],
                'mtime' => $st['mtime'],
            ];
        });
    }

    // ---------- volume management ----------

    /**
     * Create a new volume file in the user's files and FAT32-format it.
     * @return array{fileId:int}
     */
    public function createVolume(string $uid, string $name, int $sizeMb, string $password): array
    {
        if (!preg_match('/\.hc$/i', $name)) {
            $name .= '.hc';
        }
        if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9 _.\-]{0,100}\.hc$/i', $name)) {
            throw new VaultException('Bad file name', 400);
        }
        if ($sizeMb < 35 || $sizeMb > 2048) {
            throw new VaultException('Size must be 35–2048 MiB', 400);
        }
        if (strlen($password) < 8) {
            throw new VaultException('Password must be at least 8 characters', 400);
        }
        $userFolder = $this->rootFolder->getUserFolder($uid);
        if ($userFolder->nodeExists($name)) {
            throw new VaultException('A file with that name already exists', 400);
        }
        // create via Nextcloud so quota/permissions apply, then open raw
        $node = $userFolder->newFile($name);
        $local = $this->getLocalPath($node);
        // newFile created a 0-byte file; replace it with the volume
        try {
            $vol = VeraCryptVolume::create($local, $password, $sizeMb * 1024 * 1024);
        } catch (VolumeException $e) {
            $node->delete();
            throw new VaultException('Could not create volume: ' . $e->getMessage(), 500);
        }
        try {
            FatVolume::format($vol, 'CRYPTVAULT');
        } catch (VolumeException $e) {
            $vol->close();
            $node->delete();
            throw new VaultException('Could not format volume: ' . $e->getMessage(), 500);
        }
        $vol->close();
        $node->touch();
        return ['fileId' => $node->getId(), 'name' => $name];
    }

    public function changePassword(string $uid, string $token, int $fileId, string $password, int $pim, string $newPassword): void
    {
        if (strlen($newPassword) < 8) {
            throw new VaultException('Password must be at least 8 characters', 400);
        }
        $this->doWithSession($uid, $token, $fileId, $password, $pim, function ($c) use ($newPassword) {
            $this->assertUpdateable($c['node']);
            $this->withLock($c['fileId'], function () use ($c, $newPassword) {
                try {
                    $c['vol']->changePassword($newPassword);
                } catch (VolumeException $e) {
                    throw new VaultException($e->getMessage(), 400);
                }
            });
            $c['node']->touch();
        });
        // the cached header key is now stale — force re-unlock
        if ($token !== '') {
            $this->tokenDelete($token);
        }
    }

    /** Return the 512-byte encrypted header backup for download. */
    public function headerBackup(string $uid, string $token, int $fileId, string $password, int $pim): string
    {
        $c = $this->openSession($uid, $token, $fileId, $password, $pim);
        try {
            $tmp = tempnam(sys_get_temp_dir(), 'cvhdr');
            try {
                $c['vol']->backupHeader($tmp);
                $data = file_get_contents($tmp);
            } finally {
                @unlink($tmp);
            }
            if ($data === false || strlen($data) !== 512) {
                throw new VaultException('Backup failed', 500);
            }
            return $data;
        } finally {
            $c['vol']->close();
        }
    }

    // ---------- helpers ----------

    private function assertUpdateable(Node $node): void
    {
        if (!$node->isUpdateable()) {
            throw new VaultException('Volume file is read-only', 403);
        }
    }

    /** Reject path traversal and absolute shenanigans; normalize to /a/b form. */
    private function assertSafePath(string $path): void
    {
        if ($path === '' || $path === '/') {
            return;
        }
        if (!str_starts_with($path, '/')) {
            throw new VaultException('Bad path', 400);
        }
        if (str_contains($path, "\0") || str_contains($path, '\\')) {
            throw new VaultException('Bad path', 400);
        }
        foreach (explode('/', $path) as $i => $part) {
            if ($i === 0) {
                continue; // leading '/' produces an empty first element
            }
            if ($part === '..' || $part === '') {
                throw new VaultException('Bad path', 400);
            }
            if (strlen($part) > 255) {
                throw new VaultException('Name too long', 400);
            }
        }
    }
}
