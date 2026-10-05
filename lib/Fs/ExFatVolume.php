<?php
declare(strict_types=1);

namespace OCA\CryptVault\Fs;

use OCA\CryptVault\Crypto\VeraCryptVolume;
use OCA\CryptVault\Crypto\VolumeException;

/**
 * exFAT reader on top of a VeraCryptVolume.
 * v1 is read-only (list/stat/read); writing is not implemented yet.
 */
class ExFatVolume
{
    private VeraCryptVolume $vol;
    private int $bytesPerSec;
    private int $secPerClus;
    private int $fatLba;      // volume LBA of FAT start
    private int $heapLba;     // volume LBA of cluster heap start
    private int $rootCluster;
    private int $clusterCount;
    private int $clusBytes;
    private int $bitmapCluster = 0;
    private int $bitmapBytes = 0;
    /** @var int[] Decompressed upcase table (65536 entries) for name hashing. */
    private array $upcase = [];

    public function __construct(VeraCryptVolume $vol)
    {
        $this->vol = $vol;
        $boot = $vol->readSectors(0);
        if (substr($boot, 3, 8) !== 'EXFAT   ') {
            throw new VolumeException('Not an exFAT filesystem');
        }
        if (substr($boot, 510, 2) !== "\x55\xAA") {
            throw new VolumeException('Bad exFAT boot signature');
        }
        $vss = $vol->getSectorSize();
        $this->bytesPerSec = 1 << ord($boot[0x6C]);
        $this->secPerClus = 1 << ord($boot[0x6D]);
        $fatOffsetSec = self::u32($boot, 0x50);   // in filesystem sectors
        $heapOffsetSec = self::u32($boot, 0x58);
        $this->rootCluster = self::u32($boot, 0x60);
        $volLengthSec = self::u64($boot, 0x48);
        // convert filesystem-sector offsets to volume LBAs
        $this->fatLba = intdiv($fatOffsetSec * $this->bytesPerSec, $vss);
        $this->heapLba = intdiv($heapOffsetSec * $this->bytesPerSec, $vss);
        $heapSectors = $volLengthSec - $heapOffsetSec;
        $this->clusterCount = intdiv($heapSectors, $this->secPerClus) + 2;
        $this->clusBytes = $this->secPerClus * $this->bytesPerSec;
        $this->locateBitmap();
        $this->upcase = $this->loadUpcase();
    }

    /** Find the allocation bitmap (entry 0x81) in the root directory. */
    private function locateBitmap(): void
    {
        $data = $this->readDirData($this->rootCluster, true);
        $n = intdiv(strlen($data), 32);
        for ($i = 0; $i < $n; $i++) {
            $e = substr($data, $i * 32, 32);
            $t = ord($e[0]);
            if ($t === 0x00) {
                break;
            }
            if ($t === 0x81) {
                $this->bitmapCluster = self::u32($e, 20);
                $this->bitmapBytes = (int)self::u64($e, 24);
                return;
            }
        }
        throw new VolumeException('exFAT allocation bitmap not found');
    }

    /**
     * Load and decompress the upcase table (entry 0x82 in root).
     * Returns 65536-entry array mapping UTF-16 code unit -> uppercased unit.
     */
    private function loadUpcase(): array
    {
        $table = range(0, 65535); // identity default
        try {
            $data = $this->readDirData($this->rootCluster, true);
            $n = intdiv(strlen($data), 32);
            $start = 0;
            $size = 0;
            for ($i = 0; $i < $n; $i++) {
                $e = substr($data, $i * 32, 32);
                $t = ord($e[0]);
                if ($t === 0x00) {
                    break;
                }
                if ($t === 0x82) {
                    $start = self::u32($e, 20);
                    $size = (int)self::u64($e, 24);
                    break;
                }
            }
            if ($start < 2 || $size <= 0 || $size > 131072) {
                return $table;
            }
            $raw = '';
            $remaining = $size;
            $c = $start;
            while ($remaining > 0 && $c < $this->clusterCount) {
                $raw .= $this->readCluster($c);
                $remaining -= $this->clusBytes;
                $c++;
            }
            $raw = substr($raw, 0, $size);
            $inLen = intdiv(strlen($raw), 2);
            $k = 0;
            for ($i = 0; $i < $inLen && $k < 65536; $i++) {
                $ch = unpack('v', substr($raw, $i * 2, 2))[1];
                if ($ch === 0xFFFF && $i + 1 < $inLen) {
                    $i++;
                    $k += unpack('v', substr($raw, $i * 2, 2))[1];
                } else {
                    $table[$k++] = $ch;
                }
            }
        } catch (\Throwable) {
            // fall back to identity (ASCII names still hash correctly-ish)
        }
        return $table;
    }

    private static function u16(string $b, int $o): int { return unpack('v', substr($b, $o, 2))[1]; }
    private static function u32(string $b, int $o): int { return unpack('V', substr($b, $o, 4))[1]; }
    private static function u64(string $b, int $o): int
    {
        $lo = self::u32($b, $o);
        $hi = self::u32($b, $o + 4);
        return $lo + $hi * 4294967296;
    }

    private function clusterLba(int $cluster): int
    {
        $vss = $this->vol->getSectorSize();
        $fsSec = ($cluster - 2) * $this->secPerClus;
        return $this->heapLba + intdiv($fsSec * $this->bytesPerSec, $vss);
    }

    private function readCluster(int $cluster): string
    {
        $vss = $this->vol->getSectorSize();
        $nSec = intdiv($this->secPerClus * $this->bytesPerSec, $vss);
        return $this->vol->readSectors($this->clusterLba($cluster), $nSec);
    }

    private function fatGet(int $cluster): int
    {
        $vss = $this->vol->getSectorSize();
        $off = $cluster * 4; // bytes into FAT
        $lba = $this->fatLba + intdiv($off, $vss);
        $sec = $this->vol->readSectors($lba);
        return unpack('V', substr($sec, $off % $vss, 4))[1];
    }

    /** Cluster chain for a file; if $noFatChain, clusters are contiguous. */
    private function chain(int $first, bool $noFatChain, int $size): array
    {
        $clusBytes = $this->secPerClus * $this->bytesPerSec;
        $need = intdiv($size + $clusBytes - 1, $clusBytes);
        if ($need === 0) {
            return [];
        }
        if ($noFatChain) {
            $out = [];
            for ($i = 0; $i < $need; $i++) {
                $out[] = $first + $i;
            }
            return $out;
        }
        $out = [];
        $c = $first;
        $guard = 0;
        while (count($out) < $need) {
            $out[] = $c;
            $n = $this->fatGet($c);
            if ($n === 0xFFFFFFFF) {
                break;
            }
            $c = $n;
            if (++$guard > $need + 10) {
                throw new VolumeException('exFAT cluster chain loop');
            }
        }
        return $out;
    }

    private static function utf16leToUtf8(string $s, int $chars): string
    {
        $out = '';
        for ($i = 0; $i < $chars; $i++) {
            $cp = unpack('v', substr($s, $i * 2, 2))[1];
            if ($cp === 0) {
                break;
            }
            if ($cp < 0x80) {
                $out .= chr($cp);
            } elseif ($cp < 0x800) {
                $out .= chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
            } else {
                $out .= chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
            }
        }
        return $out;
    }

    private static function exfatTime(int $time, int $date): int
    {
        $y = (($date >> 9) & 0x7F) + 1980;
        $m = ($date >> 5) & 0x0F;
        $d = $date & 0x1F;
        $hh = ($time >> 11) & 0x1F;
        $mm = ($time >> 5) & 0x3F;
        $ss = ($time & 0x1F) * 2;
        return @mktime($hh, $mm, $ss, $m, $d, $y) ?: 0;
    }

    private function hasEndMarker(string $data): bool
    {
        $n = intdiv(strlen($data), 32);
        for ($i = 0; $i < $n; $i++) {
            if (ord($data[$i * 32]) === 0x00) {
                return true;
            }
        }
        return false;
    }

    /** Raw bytes of a directory (stops at end marker for contiguous dirs). */
    private function readDirData(int $firstCluster, bool $noFatChain): string
    {
        $data = '';
        if ($firstCluster >= 2) {
            if ($noFatChain) {
                for ($c = $firstCluster; $c < $this->clusterCount; $c++) {
                    $data .= $this->readCluster($c);
                    if ($this->hasEndMarker($data)) {
                        break;
                    }
                    if (strlen($data) > 16 * 1024 * 1024) {
                        break;
                    }
                }
            } else {
                $c = $firstCluster;
                $guard = 0;
                while ($c < 0xFFFFFFF8 && $guard++ < 100000) {
                    $data .= $this->readCluster($c);
                    $c = $this->fatGet($c);
                }
            }
        }
        return $data;
    }

    /**
     * Parse a directory (given first cluster + noFatChain flag).
     * Returns name => entry (each with 'entryOffset' = byte offset of its
     * file-entry slot within the directory data, for in-place updates).
     */
    private function parseDir(int $firstCluster, bool $noFatChain): array
    {
        $entries = [];
        $data = $this->readDirData($firstCluster, $noFatChain);
        $n = intdiv(strlen($data), 32);
        $i = 0;
        while ($i < $n) {
            $e = substr($data, $i * 32, 32);
            $type = ord($e[0]);
            if ($type === 0x00) {
                break;
            }
            $inUse = ($type & 0x80) !== 0;
            $type &= 0x7F;
            if (!$inUse) {
                $i++;
                continue;
            }
            if ($type === 0x05) { // file entry
                $entryOffset = $i * 32;
                $secondaryCount = ord($e[1]);
                $attrs = self::u16($e, 4);
                $mtime = self::exfatTime(self::u16($e, 12), self::u16($e, 14));
                $j = $i + 1;
                $stream = null;
                $name = '';
                $nameLen = 0;
                for ($k = 0; $k < $secondaryCount && $j < $n; $k++, $j++) {
                    $se = substr($data, $j * 32, 32);
                    $st = ord($se[0]) & 0x7F;
                    if (!((ord($se[0]) & 0x80) !== 0)) {
                        continue;
                    }
                    if ($st === 0x40) { // stream extension
                        $flags = ord($se[1]);
                        $nameLen = ord($se[3]);
                        $stream = [
                            'noFatChain' => (bool)($flags & 0x02),
                            'firstCluster' => self::u32($se, 20),
                            'dataLength' => self::u64($se, 24),
                        ];
                    } elseif ($st === 0x41) { // file name
                        $name .= substr($se, 2, 30);
                    }
                }
                if ($stream !== null) {
                    $name = self::utf16leToUtf8($name, $nameLen);
                    if ($name !== '') {
                        $entries[$name] = [
                            'name' => $name,
                            'isDir' => (bool)($attrs & 0x10),
                            'size' => $stream['dataLength'],
                            'mtime' => $mtime,
                            'cluster' => $stream['firstCluster'],
                            'noFatChain' => $stream['noFatChain'],
                            'entryOffset' => $entryOffset,
                            'secondaryCount' => $secondaryCount,
                        ];
                    }
                }
                $i = $j;
                continue;
            }
            $i++;
        }
        return $entries;
    }

    private function resolve(string $path): array
    {
        // returns [parentEntries, leafName] or dir entries for '/'
        $path = '/' . trim($path, '/');
        $parts = $path === '/' ? [] : array_values(array_filter(explode('/', $path)));
        $entries = $this->parseDir($this->rootCluster, true);
        $cur = $entries;
        $curClus = $this->rootCluster;
        $curNoFat = true;
        foreach ($parts as $idx => $part) {
            $last = $idx === count($parts) - 1;
            if (!isset($cur[$part])) {
                throw new VolumeException('Not found: ' . $path);
            }
            if ($last) {
                return [$cur, $part];
            }
            $e = $cur[$part];
            if (!$e['isDir']) {
                throw new VolumeException('Not a directory: ' . $path);
            }
            $cur = $this->parseDir($e['cluster'], $e['noFatChain']);
        }
        return [$cur, ''];
    }

    public function listDir(string $path): array
    {
        [$entries, $leaf] = $this->resolve($path);
        if ($leaf !== '') {
            $e = $entries[$leaf] ?? null;
            if ($e === null || !$e['isDir']) {
                throw new VolumeException('Not a directory: ' . $path);
            }
            $entries = $this->parseDir($e['cluster'], $e['noFatChain']);
        }
        $dirs = $files = [];
        foreach ($entries as $e) {
            if ($e['isDir']) {
                $dirs[] = $e;
            } else {
                $files[] = $e;
            }
        }
        usort($dirs, fn($a, $b) => strcasecmp($a['name'], $b['name']));
        usort($files, fn($a, $b) => strcasecmp($a['name'], $b['name']));
        return array_merge($dirs, $files);
    }

    public function stat(string $path): array
    {
        if (trim($path, '/') === '') {
            return ['name' => '/', 'isDir' => true, 'size' => 0, 'mtime' => time()];
        }
        [$entries, $leaf] = $this->resolve($path);
        if (!isset($entries[$leaf])) {
            throw new VolumeException('Not found: ' . $path);
        }
        return $entries[$leaf];
    }

    public function readFile(string $path, ?callable $chunkCb = null, int $offset = 0, ?int $length = null): string
    {
        $st = $this->stat($path);
        if ($st['isDir']) {
            throw new VolumeException('Is a directory: ' . $path);
        }
        $size = $st['size'];
        if ($length === null) {
            $length = $size - $offset;
        }
        $length = max(0, min($length, $size - $offset));
        if ($length === 0 || $st['cluster'] < 2) {
            return '';
        }
        $out = '';
        $clusBytes = $this->secPerClus * $this->bytesPerSec;
        $clusters = $this->chain($st['cluster'], $st['noFatChain'], $size);
        $pos = 0;
        foreach ($clusters as $c) {
            if ($pos + $clusBytes <= $offset) {
                $pos += $clusBytes;
                continue;
            }
            $data = $this->readCluster($c);
            $start = max(0, $offset - $pos);
            $take = min($clusBytes - $start, $offset + $length - $pos - $start);
            if ($take <= 0) {
                break;
            }
            $chunk = substr($data, $start, $take);
            if ($chunkCb) {
                $chunkCb($chunk);
            } else {
                $out .= $chunk;
            }
            $pos += $clusBytes;
            if ($pos >= $offset + $length) {
                break;
            }
        }
        return $out;
    }

    // ==================== writing ====================

    private function checkWritable(): void
    {
        if ($this->vol->isReadOnly()) {
            throw new VolumeException('Volume is mounted read-only');
        }
    }

    /** Clusters (in order) backing $bytes of a dir/file. */
    private function dirClusters(int $first, bool $noFatChain, int $bytes): array
    {
        $need = intdiv($bytes + $this->clusBytes - 1, $this->clusBytes);
        if ($noFatChain) {
            $out = [];
            for ($i = 0; $i < $need; $i++) {
                $out[] = $first + $i;
            }
            return $out;
        }
        $out = [];
        $c = $first;
        while (count($out) < $need && $c >= 2 && $c < 0xFFFFFFF8) {
            $out[] = $c;
            $c = $this->fatGet($c);
        }
        return $out;
    }

    /** Write $data at raw byte $offset within a directory's data. */
    private function writeDirData(int $first, bool $noFatChain, int $offset, string $data): void
    {
        $this->checkWritable();
        $end = $offset + strlen($data);
        $clusters = $this->dirClusters($first, $noFatChain, $end);
        $pos = 0;
        foreach ($clusters as $ci => $c) {
            $cStart = $ci * $this->clusBytes;
            $cEnd = $cStart + $this->clusBytes;
            if ($cEnd <= $offset || $cStart >= $end) {
                continue;
            }
            $chunk = $this->readCluster($c);
            $wStart = max(0, $offset - $cStart);
            $wLen = min($this->clusBytes - $wStart, $end - $cStart - $wStart);
            $chunk = substr($chunk, 0, $wStart) . substr($data, $pos, $wLen) . substr($chunk, $wStart + $wLen);
            $this->writeCluster($c, $chunk);
            $pos += $wLen;
        }
    }

    private function writeCluster(int $cluster, string $data): void
    {
        if (strlen($data) !== $this->clusBytes) {
            throw new VolumeException('exFAT cluster write size mismatch');
        }
        $vss = $this->vol->getSectorSize();
        $nSec = intdiv($this->clusBytes, $vss);
        $this->vol->writeSectors($this->clusterLba($cluster), $data);
    }

    private function fatSet(int $cluster, int $value): void
    {
        $vss = $this->vol->getSectorSize();
        $off = $cluster * 4;
        $lba = $this->fatLba + intdiv($off, $vss);
        $sec = $this->vol->readSectors($lba);
        $sec = substr($sec, 0, $off % $vss) . pack('V', $value) . substr($sec, $off % $vss + 4);
        $this->vol->writeSectors($lba, $sec);
    }

    // ---- allocation bitmap ----

    private function bitmapRead(): string
    {
        $data = '';
        $remaining = $this->bitmapBytes;
        $c = $this->bitmapCluster;
        while ($remaining > 0) {
            $data .= $this->readCluster($c);
            $remaining -= $this->clusBytes;
            $c++;
        }
        return substr($data, 0, $this->bitmapBytes);
    }

    private function bitmapWrite(string $data): void
    {
        $this->checkWritable();
        $c = $this->bitmapCluster;
        $off = 0;
        while ($off < $this->bitmapBytes) {
            $chunk = substr($data, $off, $this->clusBytes);
            $chunk = str_pad($chunk, $this->clusBytes, "\0");
            $this->writeCluster($c, $chunk);
            $off += $this->clusBytes;
            $c++;
        }
    }

    private function bitmapGet(string $bmp, int $cluster): bool
    {
        $bit = $cluster - 2;
        return ((ord($bmp[$bit >> 3]) >> ($bit & 7)) & 1) === 1;
    }

    private function bitmapPut(string &$bmp, int $cluster, bool $used): void
    {
        $bit = $cluster - 2;
        $i = $bit >> 3;
        $mask = 1 << ($bit & 7);
        $b = ord($bmp[$i]);
        $bmp[$i] = chr($used ? ($b | $mask) : ($b & ~$mask));
    }

    /**
     * Allocate $count contiguous clusters. Returns first cluster.
     * Marks them used in the bitmap.
     */
    private function allocClusters(int $count): int
    {
        $this->checkWritable();
        if ($count < 1) {
            throw new VolumeException('Nothing to allocate');
        }
        $bmp = $this->bitmapRead();
        $runStart = -1;
        $runLen = 0;
        for ($c = 2; $c < $this->clusterCount; $c++) {
            if (!$this->bitmapGet($bmp, $c)) {
                if ($runStart < 0) {
                    $runStart = $c;
                }
                if (++$runLen === $count) {
                    for ($i = 0; $i < $count; $i++) {
                        $this->bitmapPut($bmp, $runStart + $i, true);
                    }
                    $this->bitmapWrite($bmp);
                    return $runStart;
                }
            } else {
                $runStart = -1;
                $runLen = 0;
            }
        }
        throw new VolumeException('Disk full (no contiguous run of ' . $count . ' clusters)');
    }

    private function freeClusters(int $first, int $count): void
    {
        $this->checkWritable();
        $bmp = $this->bitmapRead();
        for ($i = 0; $i < $count; $i++) {
            $this->bitmapPut($bmp, $first + $i, false);
        }
        $this->bitmapWrite($bmp);
    }

    // ---- entry set construction ----

    private static function utf8ToUtf16le(string $s): string
    {
        $out = '';
        $len = strlen($s);
        for ($i = 0; $i < $len;) {
            $c = ord($s[$i]);
            if ($c < 0x80) {
                $cp = $c;
                $i += 1;
            } elseif (($c & 0xE0) === 0xC0 && $i + 1 < $len) {
                $cp = (($c & 0x1F) << 6) | (ord($s[$i + 1]) & 0x3F);
                $i += 2;
            } elseif (($c & 0xF0) === 0xE0 && $i + 2 < $len) {
                $cp = (($c & 0x0F) << 12) | ((ord($s[$i + 1]) & 0x3F) << 6) | (ord($s[$i + 2]) & 0x3F);
                $i += 3;
            } else {
                $cp = 0x3F;
                $i += 1;
            }
            $out .= pack('v', $cp > 0xFFFF ? 0x3F : $cp);
        }
        return $out;
    }

    /** exFAT name hash: upcase each UTF-16 unit, then rotate-add per byte. */
    private function nameHash(string $utf16): int
    {
        $hash = 0;
        $len = strlen($utf16);
        for ($i = 0; $i < $len; $i += 2) {
            $unit = unpack('v', substr($utf16, $i, 2))[1];
            $ch = $this->upcase[$unit] ?? $unit;
            $lo = $ch & 0xFF;
            $hi = ($ch >> 8) & 0xFF;
            $hash = ((($hash << 15) | ($hash >> 1)) & 0xFFFF);
            $hash = ($hash + $lo) & 0xFFFF;
            $hash = ((($hash << 15) | ($hash >> 1)) & 0xFFFF);
            $hash = ($hash + $hi) & 0xFFFF;
        }
        return $hash;
    }

    /** exFAT directory-entry-set checksum (skips bytes 2-3 of first entry). */
    private static function entrySetChecksum(array $entries): int
    {
        $sum = 0;
        foreach ($entries as $ei => $e) {
            for ($j = 0; $j < 32; $j++) {
                if ($ei === 0 && ($j === 2 || $j === 3)) {
                    continue;
                }
                $sum = ((($sum & 1) ? 0x8000 : 0) + ($sum >> 1) + ord($e[$j])) & 0xFFFF;
            }
        }
        return $sum;
    }

    private static function exfatDateTime(int $ts): array
    {
        $t = getdate($ts);
        $date = (($t['year'] - 1980) << 9) | ($t['mon'] << 5) | $t['mday'];
        $time = ($t['hours'] << 11) | ($t['minutes'] << 5) | intdiv($t['seconds'], 2);
        return [$time & 0xFFFF, $date & 0xFFFF];
    }

    /**
     * Build a directory entry set for a file/dir.
     * Returns list of 32-byte entries (file, stream, name...).
     */
    private function buildEntrySet(string $name, bool $isDir, int $firstCluster, int $size): array
    {
        $utf16 = self::utf8ToUtf16le($name);
        $charCount = intdiv(strlen($utf16), 2);
        if ($charCount < 1 || $charCount > 255) {
            throw new VolumeException('Bad filename length');
        }
        $nameEntries = intdiv($charCount + 14, 15);
        [$time, $date] = self::exfatDateTime(time());
        $attr = $isDir ? 0x10 : 0x20;

        $entries = [];
        // file entry (checksum filled in later)
        $entries[] = chr(0x85) . chr(1 + $nameEntries)
            . "\0\0" // checksum placeholder
            . pack('v', $attr) . "\0\0"
            . pack('v', $time) . pack('v', $date)   // created
            . pack('v', $time) . pack('v', $date)   // modified
            . pack('v', $time) . pack('v', $date)   // accessed
            . "\0\0\0\0\0" . str_repeat("\0", 7);
        // stream extension: NoFatChain (contiguous allocation)
        $entries[] = chr(0xC0) . chr(0x02) . "\0"
            . chr($charCount)
            . pack('v', $this->nameHash($utf16)) . "\0\0"
            . pack('P', $size) . pack('V', 0)
            . pack('V', $firstCluster) . pack('P', $size);
        // file name entries
        for ($k = 0; $k < $nameEntries; $k++) {
            $chunk = substr($utf16, $k * 30, 30);
            $entries[] = chr(0xC1) . chr(0x00) . str_pad($chunk, 30, "\0");
        }
        $checksum = self::entrySetChecksum($entries);
        $entries[0] = substr($entries[0], 0, 2) . pack('v', $checksum) . substr($entries[0], 4);
        return $entries;
    }

    // ---- directory mutation ----

    /**
     * Locate parent dir info + leaf for $path.
     * Returns ['dir'=>['cluster'=>,'noFatChain'=>], 'name'=>leaf,
     *          'selfEntry'=>['parentDir'=>,'entryOffset'=>]|null for root].
     */
    private function resolveParentEx(string $path): array
    {
        $this->checkWritable();
        $path = '/' . trim($path, '/');
        if ($path === '/') {
            throw new VolumeException('Cannot operate on root this way');
        }
        $parts = array_values(array_filter(explode('/', $path), fn($p) => $p !== ''));
        $leaf = array_pop($parts);
        $dir = ['cluster' => $this->rootCluster, 'noFatChain' => true];
        $selfEntry = null;
        foreach ($parts as $part) {
            $entries = $this->parseDir($dir['cluster'], $dir['noFatChain']);
            if (!isset($entries[$part]) || !$entries[$part]['isDir']) {
                throw new VolumeException('Path not found: ' . $path);
            }
            $e = $entries[$part];
            $selfEntry = ['parentDir' => $dir, 'entryOffset' => $e['entryOffset'], 'secondaryCount' => $e['secondaryCount']];
            $dir = ['cluster' => $e['cluster'], 'noFatChain' => $e['noFatChain']];
        }
        return ['dir' => $dir, 'name' => $leaf, 'selfEntry' => $selfEntry];
    }

    /**
     * Find a run of $need free 32-byte slots in a directory; extends the
     * directory if necessary. Returns byte offset of the run.
     */
    private function allocDirSlots(array &$dir, int $need, ?array $selfEntry): int
    {
        $data = $this->readDirData($dir['cluster'], $dir['noFatChain']);
        $n = intdiv(strlen($data), 32);
        $run = 0;
        $runStart = 0;
        for ($i = 0; $i < $n; $i++) {
            $t = ord($data[$i * 32]);
            if ($t === 0x00 || ($t & 0x80) === 0) {
                if ($run === 0) {
                    $runStart = $i * 32;
                }
                if (++$run === $need) {
                    return $runStart;
                }
            } else {
                $run = 0;
            }
        }
        // no room: extend the directory by one cluster
        $used = max(1, intdiv(strlen($data) + $this->clusBytes - 1, $this->clusBytes));
        if ($dir['noFatChain']) {
            $next = $dir['cluster'] + $used;
            $bmp = $this->bitmapRead();
            if ($next < $this->clusterCount && !$this->bitmapGet($bmp, $next)) {
                $this->bitmapPut($bmp, $next, true);
                $this->bitmapWrite($bmp);
                $this->writeCluster($next, str_repeat("\0", $this->clusBytes));
                return $used * $this->clusBytes;
            }
        }
        // convert to (or extend) a FAT chain
        $newClus = $this->allocClusters(1);
        $this->writeCluster($newClus, str_repeat("\0", $this->clusBytes));
        $clusters = $this->dirClusters($dir['cluster'], $dir['noFatChain'], strlen($data));
        if ($dir['noFatChain']) {
            for ($i = 0; $i < count($clusters); $i++) {
                $this->fatSet($clusters[$i], $i + 1 < count($clusters) ? $clusters[$i + 1] : $newClus);
            }
            $this->fatSet($newClus, 0xFFFFFFFF);
            $dir['noFatChain'] = false;
            $this->updateNoFatChainFlag($selfEntry, false);
        } else {
            $this->fatSet(end($clusters), $newClus);
            $this->fatSet($newClus, 0xFFFFFFFF);
        }
        return count($clusters) * $this->clusBytes;
    }

    /**
     * Update the NoFatChain flag of a directory's own stream entry
     * (recomputing the entry-set checksum). $selfEntry is null for root.
     */
    private function updateNoFatChainFlag(?array $selfEntry, bool $noFatChain): void
    {
        if ($selfEntry === null) {
            return; // root: only contiguous extension is used
        }
        $pd = $selfEntry['parentDir'];
        $off = $selfEntry['entryOffset'];
        $total = 1 + $selfEntry['secondaryCount'];
        $set = [];
        for ($i = 0; $i < $total; $i++) {
            $set[] = $this->readDirEntryRaw($pd, $off + $i * 32);
        }
        // stream entry is $set[1]; flags at byte 1
        $se = $set[1];
        $se[1] = chr($noFatChain ? (ord($se[1]) | 0x02) : (ord($se[1]) & ~0x02));
        $set[1] = $se;
        $checksum = self::entrySetChecksum($set);
        $set[0] = substr($set[0], 0, 2) . pack('v', $checksum) . substr($set[0], 4);
        for ($i = 0; $i < $total; $i++) {
            $this->writeDirEntryRaw($pd, $off + $i * 32, $set[$i]);
        }
    }

    private function readDirEntryRaw(array $dir, int $offset): string
    {
        $clusters = $this->dirClusters($dir['cluster'], $dir['noFatChain'], $offset + 32);
        $ci = intdiv($offset, $this->clusBytes);
        $chunk = $this->readCluster($clusters[$ci]);
        return substr($chunk, $offset % $this->clusBytes, 32);
    }

    private function writeDirEntryRaw(array $dir, int $offset, string $entry32): void
    {
        $clusters = $this->dirClusters($dir['cluster'], $dir['noFatChain'], $offset + 32);
        $ci = intdiv($offset, $this->clusBytes);
        $chunk = $this->readCluster($clusters[$ci]);
        $inOff = $offset % $this->clusBytes;
        $chunk = substr($chunk, 0, $inOff) . $entry32 . substr($chunk, $inOff + 32);
        $this->writeCluster($clusters[$ci], $chunk);
    }

    public function mkdir(string $path): void
    {
        $r = $this->resolveParentEx($path);
        $entries = $this->parseDir($r['dir']['cluster'], $r['dir']['noFatChain']);
        if (isset($entries[$r['name']])) {
            throw new VolumeException('Already exists: ' . $path);
        }
        $clus = $this->allocClusters(1);
        $this->writeCluster($clus, str_repeat("\0", $this->clusBytes));
        $set = $this->buildEntrySet($r['name'], true, $clus, $this->clusBytes);
        $off = $this->allocDirSlots($r['dir'], count($set), $r['selfEntry']);
        $this->writeDirData($r['dir']['cluster'], $r['dir']['noFatChain'], $off, implode('', $set));
    }

    public function writeFile(string $path, $source): void
    {
        $r = $this->resolveParentEx($path);
        $entries = $this->parseDir($r['dir']['cluster'], $r['dir']['noFatChain']);
        $isStream = is_resource($source);

        // collect content
        $content = '';
        if ($isStream) {
            while (!feof($source)) {
                $chunk = fread($source, 1048576);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $content .= $chunk;
            }
        } else {
            $content = (string)$source;
        }
        $size = strlen($content);
        $needClus = max(1, intdiv($size + $this->clusBytes - 1, $this->clusBytes));

        if (isset($entries[$r['name']])) {
            $old = $entries[$r['name']];
            if ($old['isDir']) {
                throw new VolumeException('Is a directory: ' . $path);
            }
            // free old clusters (contiguous run)
            $oldClus = intdiv($old['size'] + $this->clusBytes - 1, $this->clusBytes);
            if ($old['cluster'] >= 2 && $oldClus > 0) {
                $this->freeClusters($old['cluster'], max(1, $oldClus));
            }
            $first = $this->allocClusters($needClus);
            $this->writeFileClusters($first, $content);
            // update stream entry in place (size + first cluster)
            $set = $this->buildEntrySet($r['name'], false, $first, $size);
            // keep the same slot: rewrite whole entry set
            $off = $old['entryOffset'];
            $this->writeDirData($r['dir']['cluster'], $r['dir']['noFatChain'], $off, implode('', $set));
        } else {
            $first = $this->allocClusters($needClus);
            $this->writeFileClusters($first, $content);
            $set = $this->buildEntrySet($r['name'], false, $first, $size);
            $off = $this->allocDirSlots($r['dir'], count($set), $r['selfEntry']);
            $this->writeDirData($r['dir']['cluster'], $r['dir']['noFatChain'], $off, implode('', $set));
        }
    }

    private function writeFileClusters(int $first, string $content): void
    {
        $off = 0;
        $c = $first;
        $len = strlen($content);
        while ($off < $len) {
            $chunk = substr($content, $off, $this->clusBytes);
            $this->writeCluster($c, str_pad($chunk, $this->clusBytes, "\0"));
            $off += $this->clusBytes;
            $c++;
        }
        if ($len === 0) {
            $this->writeCluster($first, str_repeat("\0", $this->clusBytes));
        }
    }

    public function delete(string $path): void
    {
        $r = $this->resolveParentEx($path);
        $entries = $this->parseDir($r['dir']['cluster'], $r['dir']['noFatChain']);
        if (!isset($entries[$r['name']])) {
            throw new VolumeException('Not found: ' . $path);
        }
        $e = $entries[$r['name']];
        if ($e['isDir']) {
            $children = $this->parseDir($e['cluster'], $e['noFatChain']);
            if (!empty($children)) {
                throw new VolumeException('Directory not empty: ' . $path);
            }
        }
        $clusCount = max(1, intdiv($e['size'] + $this->clusBytes - 1, $this->clusBytes));
        if ($e['cluster'] >= 2) {
            if ($e['noFatChain']) {
                $this->freeClusters($e['cluster'], $clusCount);
            } else {
                // free via FAT chain
                $c = $e['cluster'];
                $bmp = $this->bitmapRead();
                while ($c >= 2 && $c < 0xFFFFFFF8) {
                    $n = $this->fatGet($c);
                    $this->bitmapPut($bmp, $c, false);
                    $this->fatSet($c, 0);
                    $c = $n;
                }
                $this->bitmapWrite($bmp);
            }
        }
        // mark entry set inactive (clear 0x80 on each entry of the set)
        $off = $e['entryOffset'];
        $total = 1 + $e['secondaryCount'];
        for ($i = 0; $i < $total; $i++) {
            $slot = $off + $i * 32;
            $clusters = $this->dirClusters($r['dir']['cluster'], $r['dir']['noFatChain'], $slot + 1);
            $ci = intdiv($slot, $this->clusBytes);
            $inOff = $slot % $this->clusBytes;
            $chunk = $this->readCluster($clusters[$ci]);
            $chunk[$inOff] = chr(ord($chunk[$inOff]) & 0x7F);
            $this->writeCluster($clusters[$ci], $chunk);
        }
    }
}
