<?php
declare(strict_types=1);

namespace OCA\CryptVault\Fs;

use OCA\CryptVault\Crypto\VeraCryptVolume;
use OCA\CryptVault\Crypto\VolumeException;

/**
 * FAT12/16/32 reader + writer on top of a VeraCryptVolume.
 * Focused on FAT32 (what VeraCrypt creates by default); FAT12/16 supported
 * for reading and basic writing.
 */
class FatVolume
{
    private VeraCryptVolume $vol;
    private int $bytesPerSec;
    private int $secPerClus;
    private int $rsvdSecCnt;
    private int $numFATs;
    private int $fatSz;          // sectors per FAT
    private int $totSec;
    private int $rootClus;       // FAT32
    private int $firstDataSec;
    private int $fatType;        // 12, 16, 32
    private int $rootDirSecs;    // FAT12/16
    private int $firstRootDirSec;// FAT12/16

    public function __construct(VeraCryptVolume $vol)
    {
        $this->vol = $vol;
        $boot = $vol->readSectors(0);
        if (substr($boot, 510, 2) !== "\x55\xAA") {
            throw new VolumeException('Not a FAT filesystem (bad boot signature)');
        }
        $this->bytesPerSec = self::u16($boot, 11);
        $this->secPerClus  = ord($boot[13]);
        $this->rsvdSecCnt  = self::u16($boot, 14);
        $this->numFATs     = ord($boot[16]);
        $tot16 = self::u16($boot, 19);
        $this->totSec      = $tot16 !== 0 ? $tot16 : self::u32($boot, 32);
        $fat16 = self::u16($boot, 22);
        $this->fatSz       = $fat16 !== 0 ? $fat16 : self::u32($boot, 36);
        $this->rootClus    = self::u32($boot, 44);
        $rootEntCnt        = self::u16($boot, 17);

        if ($this->bytesPerSec === 0 || $this->secPerClus === 0) {
            throw new VolumeException('Invalid FAT boot sector');
        }
        // VeraCrypt volume sector size should match the FS sector size for our math
        $this->firstDataSec = $this->rsvdSecCnt + $this->numFATs * $this->fatSz;
        $dataSecs = $this->totSec - $this->firstDataSec;
        $countOfClusters = intdiv($dataSecs, $this->secPerClus);
        if ($countOfClusters < 4085) {
            $this->fatType = 12;
        } elseif ($countOfClusters < 65525) {
            $this->fatType = 16;
        } else {
            $this->fatType = 32;
        }
        $this->rootDirSecs = intdiv($rootEntCnt * 32 + $this->bytesPerSec - 1, $this->bytesPerSec);
        $this->firstRootDirSec = $this->firstDataSec - $this->rootDirSecs;
    }

    // ---------- low-level helpers ----------

    private static function u16(string $b, int $o): int { return unpack('v', substr($b, $o, 2))[1]; }
    private static function u32(string $b, int $o): int { return unpack('V', substr($b, $o, 4))[1]; }

    private function clusterToLba(int $cluster): int
    {
        // volume LBA (in volume sectors) of first sector of cluster
        $fsSector = $this->firstDataSec + ($cluster - 2) * $this->secPerClus;
        // convert FS sectors to volume sectors (usually 1:1)
        $vss = $this->vol->getSectorSize();
        return intdiv($fsSector * $this->bytesPerSec, $vss);
    }

    private function readCluster(int $cluster): string
    {
        $lba = $this->clusterToLba($cluster);
        $nSec = intdiv($this->secPerClus * $this->bytesPerSec, $this->vol->getSectorSize());
        return $this->vol->readSectors($lba, $nSec);
    }

    private function writeCluster(int $cluster, string $data): void
    {
        $want = $this->secPerClus * $this->bytesPerSec;
        if (strlen($data) !== $want) {
            throw new VolumeException('Cluster write size mismatch');
        }
        $lba = $this->clusterToLba($cluster);
        $nSec = intdiv($want, $this->vol->getSectorSize());
        $this->vol->writeSectors($lba, $data);
    }

    /** Read one FAT entry for $cluster. */
    private function fatGet(int $cluster): int
    {
        $vss = $this->vol->getSectorSize();
        if ($this->fatType === 32) {
            $off = $cluster * 4;
            $lba = intdiv($this->rsvdSecCnt * $this->bytesPerSec + $off, $vss);
            $sec = $this->vol->readSectors($lba);
            $val = unpack('V', substr($sec, ($this->rsvdSecCnt * $this->bytesPerSec + $off) % $vss, 4))[1];
            return $val & 0x0FFFFFFF;
        }
        if ($this->fatType === 16) {
            $off = $cluster * 2;
            $lba = intdiv($this->rsvdSecCnt * $this->bytesPerSec + $off, $vss);
            $sec = $this->vol->readSectors($lba);
            return unpack('v', substr($sec, ($this->rsvdSecCnt * $this->bytesPerSec + $off) % $vss, 2))[1];
        }
        // FAT12
        $off = intdiv($cluster * 3, 2);
        $lba = intdiv($this->rsvdSecCnt * $this->bytesPerSec + $off, $vss);
        $sec = $this->vol->readSectors($lba);
        $base = ($this->rsvdSecCnt * $this->bytesPerSec + $off) % $vss;
        $w = unpack('v', substr($sec . $this->vol->readSectors($lba + 1), $base, 2))[1];
        return ($cluster & 1) ? ($w >> 4) : ($w & 0x0FFF);
    }

    private function fatIsEoc(int $v): bool
    {
        return $this->fatType === 32 ? $v >= 0x0FFFFFF8 : ($this->fatType === 16 ? $v >= 0xFFF8 : $v >= 0x0FF8);
    }

    /** Write one FAT entry (mirrored to all FATs). */
    private function fatSet(int $cluster, int $value): void
    {
        $vss = $this->vol->getSectorSize();
        $fatBytes = $this->fatSz * $this->bytesPerSec;
        for ($f = 0; $f < $this->numFATs; $f++) {
            $fatBase = ($this->rsvdSecCnt * $this->bytesPerSec) + $f * $fatBytes;
            if ($this->fatType === 32) {
                $off = $fatBase + $cluster * 4;
                $lba = intdiv($off, $vss);
                $sec = $this->vol->readSectors($lba);
                $cur = unpack('V', substr($sec, $off % $vss, 4))[1];
                $new = ($cur & 0xF0000000) | ($value & 0x0FFFFFFF);
                $sec = substr($sec, 0, $off % $vss) . pack('V', $new) . substr($sec, $off % $vss + 4);
                $this->vol->writeSectors($lba, $sec);
            } elseif ($this->fatType === 16) {
                $off = $fatBase + $cluster * 2;
                $lba = intdiv($off, $vss);
                $sec = $this->vol->readSectors($lba);
                $sec = substr($sec, 0, $off % $vss) . pack('v', $value & 0xFFFF) . substr($sec, $off % $vss + 2);
                $this->vol->writeSectors($lba, $sec);
            } else {
                // FAT12: read-modify-write 2 bytes (may span sectors)
                $off = $fatBase + intdiv($cluster * 3, 2);
                $lba = intdiv($off, $vss);
                $inSec = $off % $vss;
                $sec = $this->vol->readSectors($lba);
                if ($inSec === $vss - 1) {
                    $sec .= $this->vol->readSectors($lba + 1);
                }
                $w = unpack('v', substr($sec, $inSec, 2))[1];
                $w = ($cluster & 1) ? (($w & 0x000F) | (($value & 0x0FFF) << 4)) : (($w & 0xF000) | ($value & 0x0FFF));
                $sec = substr($sec, 0, $inSec) . pack('v', $w) . substr($sec, $inSec + 2);
                $this->vol->writeSectors($lba, substr($sec, 0, $vss));
                if ($inSec === $vss - 1) {
                    $this->vol->writeSectors($lba + 1, substr($sec, $vss, $vss));
                }
            }
        }
    }

    /** Follow a cluster chain, returning all data clusters (EOC marker excluded). */
    private function chain(int $start): array
    {
        $out = [];
        $c = $start;
        $guard = 0;
        while ($c >= 2 && !$this->fatIsEoc($c)) {
            $out[] = $c;
            $c = $this->fatGet($c);
            if (++$guard > 10000000) {
                throw new VolumeException('Cluster chain loop detected (corrupt filesystem?)');
            }
        }
        return $out;
    }

    /** Find a free cluster (simple linear scan). */
    private function allocCluster(): int
    {
        $dataSecs = $this->totSec - $this->firstDataSec;
        $count = intdiv($dataSecs, $this->secPerClus) + 2;
        for ($c = 2; $c < $count; $c++) {
            if ($this->fatGet($c) === 0) {
                return $c;
            }
        }
        throw new VolumeException('Disk full (no free clusters)');
    }

    private function freeChain(int $start): void
    {
        foreach ($this->chain($start) as $c) {
            $this->fatSet($c, 0);
        }
    }

    // ---------- directory handling ----------

    /**
     * Read raw directory entries of a directory given its starting cluster
     * (0 = FAT12/16 root). Returns list of ['raw'=>32B, 'lba'=>, 'off'=>] slots.
     */
    private function readDirSlots(int $startCluster): array
    {
        $slots = [];
        $vss = $this->vol->getSectorSize();
        if ($startCluster === 0) {
            // FAT12/16 fixed root
            for ($s = 0; $s < $this->rootDirSecs; $s++) {
                $lba = intdiv(($this->firstRootDirSec + $s) * $this->bytesPerSec, $vss);
                $nSec = intdiv($this->bytesPerSec, $vss);
                $data = $this->vol->readSectors($lba, $nSec);
                for ($o = 0; $o < strlen($data); $o += 32) {
                    $slots[] = ['raw' => substr($data, $o, 32), 'lba' => $lba, 'off' => $o, 'fixedRoot' => true];
                }
            }
            return $slots;
        }
        foreach ($this->chain($startCluster) as $c) {
            $data = $this->readCluster($c);
            $lba = $this->clusterToLba($c);
            $perSec = intdiv($vss, 32);
            for ($o = 0; $o < strlen($data); $o += 32) {
                $slots[] = ['raw' => substr($data, $o, 32), 'lba' => $lba + intdiv($o, $vss), 'off' => $o % $vss, 'fixedRoot' => false];
            }
        }
        return $slots;
    }

    private static function utf16leToUtf8(string $s): string
    {
        $out = '';
        for ($i = 0; $i + 1 < strlen($s); $i += 2) {
            $cp = unpack('v', substr($s, $i, 2))[1];
            if ($cp === 0 || $cp === 0xFFFF) {
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

    private static function utf8ToUtf16le(string $s): string
    {
        // BMP-only, sufficient for filenames
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
                $i += 1; // skip (no surrogate support)
            }
            $out .= pack('v', $cp > 0xFFFF ? 0x3F : $cp);
        }
        return $out;
    }

    private static function fatDateTime(int $date, int $time): int
    {
        $y = (($date >> 9) & 0x7F) + 1980;
        $m = ($date >> 5) & 0x0F;
        $d = $date & 0x1F;
        $hh = ($time >> 11) & 0x1F;
        $mm = ($time >> 5) & 0x3F;
        $ss = ($time & 0x1F) * 2;
        return @mktime($hh, $mm, $ss, $m, $d, $y) ?: 0;
    }

    /**
     * Parse directory slots into entries.
     * Returns [name => ['name','isDir','size','mtime','cluster','slots'=>[...]]]
     */
    private function parseDir(int $startCluster): array
    {
        $slots = $this->readDirSlots($startCluster);
        $entries = [];
        $lfn = '';
        $lfnParts = [];
        foreach ($slots as $idx => $slot) {
            $raw = $slot['raw'];
            $first = ord($raw[0]);
            if ($first === 0x00) {
                break; // end of directory
            }
            $attr = ord($raw[11]);
            if ($first === 0xE5) {
                $lfn = '';
                $lfnParts = [];
                continue; // deleted
            }
            if ($attr === 0x0F) {
                // LFN entry
                $seq = ord($raw[0]) & 0x1F;
                $part = substr($raw, 1, 10) . substr($raw, 14, 12) . substr($raw, 28, 4);
                $lfnParts[$seq] = $part;
                continue;
            }
            if ($attr & 0x08) {
                $lfnParts = [];
                continue; // volume label
            }
            $name = '';
            if (!empty($lfnParts)) {
                ksort($lfnParts);
                $name = self::utf16leToUtf8(implode('', $lfnParts));
                $lfnParts = [];
            } else {
                $base = rtrim(substr($raw, 0, 8));
                $ext = rtrim(substr($raw, 8, 3));
                if ($first === 0x05) {
                    $base = "\xE5" . substr($base, 1);
                }
                $name = $ext !== '' ? $base . '.' . $ext : $base;
            }
            if ($name === '' || $name === '.' || $name === '..') {
                continue;
            }
            $cluster = self::u16($raw, 26) | (self::u16($raw, 20) << 16);
            $entries[$name] = [
                'name' => $name,
                'isDir' => (bool)($attr & 0x10),
                'size' => self::u32($raw, 28),
                'mtime' => self::fatDateTime(self::u16($raw, 24), self::u16($raw, 22)),
                'cluster' => $cluster,
                'attr' => $attr,
                'slotIdx' => $idx,
            ];
        }
        return $entries;
    }

    /** Resolve a path like "/docs/report.pdf" to parent info + leaf name. */
    private function resolveParent(string $path): array
    {
        $path = '/' . trim($path, '/');
        if ($path === '/') {
            return ['parentCluster' => $this->fatType === 32 ? $this->rootClus : 0, 'name' => '', 'isRoot' => true];
        }
        $parts = array_values(array_filter(explode('/', $path), fn($p) => $p !== ''));
        $leaf = array_pop($parts);
        $cluster = $this->fatType === 32 ? $this->rootClus : 0;
        foreach ($parts as $part) {
            $entries = $this->parseDir($cluster);
            if (!isset($entries[$part]) || !$entries[$part]['isDir']) {
                throw new VolumeException("Path not found: /" . implode('/', $parts));
            }
            $cluster = $entries[$part]['cluster'];
        }
        return ['parentCluster' => $cluster, 'name' => $leaf, 'isRoot' => false];
    }

    public function listDir(string $path): array
    {
        $r = $this->resolveParent($path);
        if ($r['isRoot']) {
            $entries = $this->parseDir($r['parentCluster']);
        } else {
            // resolve the dir itself
            $parent = $this->parseDir($r['parentCluster']);
            if (!isset($parent[$r['name']]) || !$parent[$r['name']]['isDir']) {
                throw new VolumeException("Not a directory: $path");
            }
            $entries = $this->parseDir($parent[$r['name']]['cluster']);
        }
        // sort: dirs first, then alpha
        uasort($entries, fn($a, $b) => [$b['isDir'] <=> $a['isDir'], strcasecmp($a['name'], $b['name'])][0] ?? 0);
        // simpler stable sort
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
        $r = $this->resolveParent($path);
        if ($r['isRoot']) {
            return ['name' => '/', 'isDir' => true, 'size' => 0, 'mtime' => time(), 'cluster' => $r['parentCluster']];
        }
        $entries = $this->parseDir($r['parentCluster']);
        if (!isset($entries[$r['name']])) {
            throw new VolumeException("Not found: $path");
        }
        return $entries[$r['name']];
    }

    /**
     * Read a file. For large files use $chunkCb callback to stream:
     * readFile($path, function($bytes){...}).
     */
    public function readFile(string $path, ?callable $chunkCb = null, int $offset = 0, ?int $length = null): string
    {
        $st = $this->stat($path);
        if ($st['isDir']) {
            throw new VolumeException("Is a directory: $path");
        }
        $size = $st['size'];
        if ($length === null) {
            $length = $size - $offset;
        }
        $length = max(0, min($length, $size - $offset));
        $out = '';
        if ($length === 0) {
            return '';
        }
        $clusSize = $this->secPerClus * $this->bytesPerSec;
        $clusters = $this->chain($st['cluster']);
        $pos = 0; // position within file
        foreach ($clusters as $c) {
            if ($pos + $clusSize <= $offset) {
                $pos += $clusSize;
                continue;
            }
            $data = $this->readCluster($c);
            $start = max(0, $offset - $pos);
            $take = min($clusSize - $start, $offset + $length - $pos - $start);
            if ($take <= 0) {
                break;
            }
            $chunk = substr($data, $start, $take);
            if ($chunkCb) {
                $chunkCb($chunk);
            } else {
                $out .= $chunk;
            }
            $pos += $clusSize;
            if ($pos >= $offset + $length) {
                break;
            }
        }
        return $out;
    }

    // ---------- writing ----------

    private function checkWritable(): void
    {
        if ($this->vol->isReadOnly()) {
            throw new VolumeException('Volume is mounted read-only');
        }
    }

    private static function dosDateTime(int $ts): array
    {
        $t = getdate($ts);
        $date = (($t['year'] - 1980) << 9) | ($t['mon'] << 5) | $t['mday'];
        $time = ($t['hours'] << 11) | ($t['minutes'] << 5) | intdiv($t['seconds'], 2);
        return [$time & 0xFFFF, $date & 0xFFFF];
    }

    /** Build a short 8.3 name from a long name (with ~n uniquification). */
    private function shortName(string $name, array $existing): string
    {
        $name = strtoupper($name);
        // strip/replace invalid chars
        $name = preg_replace('/[^A-Z0-9$%\'\-_@~`!(){}^#&.]/', '_', $name);
        $dot = strrpos($name, '.');
        if ($dot !== false && $dot > 0) {
            $base = substr($name, 0, $dot);
            $ext = substr($name, $dot + 1, 3);
        } else {
            $base = $name;
            $ext = '';
        }
        $base = substr(preg_replace('/\.+/', '', $base), 0, 8);
        $ext = substr($ext, 0, 3);
        $pad = fn($s, $l) => str_pad($s, $l, ' ');
        $candidate = $pad($base, 8) . $pad($ext, 3);
        $taken = [];
        foreach ($existing as $e) {
            $taken[] = $e['raw83'] ?? '';
        }
        if (!in_array($candidate, $taken, true) && trim($candidate) !== '') {
            return $candidate;
        }
        for ($n = 1; $n < 100000; $n++) {
            $b = substr($base, 0, 8 - strlen((string)$n) - 1) . '~' . $n;
            $candidate = $pad($b, 8) . $pad($ext, 3);
            if (!in_array($candidate, $taken, true)) {
                return $candidate;
            }
        }
        throw new VolumeException('Cannot generate unique short name');
    }

    /** Write a 32-byte dir entry into a slot. */
    private function writeSlot(array $slot, string $raw32): void
    {
        if (strlen($raw32) !== 32) {
            throw new VolumeException('Directory entry must be exactly 32 bytes');
        }
        $sec = $this->vol->readSectors($slot['lba']);
        $sec = substr($sec, 0, $slot['off']) . $raw32 . substr($sec, $slot['off'] + 32);
        $this->vol->writeSectors($slot['lba'], $sec);
    }

    /**
     * Find $need contiguous free directory slots in $parentCluster,
     * extending the directory if necessary. Returns slot list.
     */
    private function allocDirSlots(int $parentCluster, int $need): array
    {
        $this->checkWritable();
        $slots = $this->readDirSlots($parentCluster);
        $run = [];
        foreach ($slots as $i => $slot) {
            $first = ord($slot['raw'][0]);
            if ($first === 0x00 || $first === 0xE5) {
                $run[] = $slot;
                if (count($run) === $need) {
                    return $run;
                }
            } else {
                $run = [];
            }
        }
        // extend directory (not possible for FAT12/16 fixed root)
        if ($parentCluster === 0) {
            throw new VolumeException('Root directory is full');
        }
        $clusters = $this->chain($parentCluster);
        $newClus = $this->allocCluster();
        $last = end($clusters);
        $this->fatSet($last, $newClus);
        $this->fatSet($newClus, $this->fatType === 32 ? 0x0FFFFFFF : ($this->fatType === 16 ? 0xFFFF : 0x0FFF));
        $this->writeCluster($newClus, str_repeat("\0", $this->secPerClus * $this->bytesPerSec));
        return $this->allocDirSlots($parentCluster, $need);
    }

    /** Create directory entries (LFN + short) for a new file/dir. Returns short entry info. */
    private function createEntry(int $parentCluster, string $name, bool $isDir, int $cluster, int $size): void
    {
        $this->checkWritable();
        $slots = $this->readDirSlots($parentCluster);
        $existing = [];
        foreach ($slots as $s) {
            $first = ord($s['raw'][0]);
            if ($first !== 0x00 && $first !== 0xE5 && ord($s['raw'][11]) !== 0x0F) {
                $existing[] = ['raw83' => substr($s['raw'], 0, 11)];
            }
        }
        $short83 = $this->shortName($name, $existing);
        $utf16 = self::utf8ToUtf16le($name);
        $lfnCount = intdiv(strlen($utf16) + 25, 26);
        if ($lfnCount > 20) {
            throw new VolumeException('Filename too long');
        }
        $need = $lfnCount + 1;
        $target = $this->allocDirSlots($parentCluster, $need);

        [$ftime, $fdate] = self::dosDateTime(time());
        $attr = $isDir ? 0x10 : 0x20;

        // LFN entries (stored in reverse order)
        $checksum = 0;
        for ($i = 0; $i < 11; $i++) {
            $checksum = ((($checksum >> 1) | (($checksum & 1) << 7)) + ord($short83[$i])) & 0xFF;
        }
        for ($e = $lfnCount; $e >= 1; $e--) {
            $chunk = substr($utf16, ($e - 1) * 26, 26);
            $chunk = str_pad($chunk, 26, "\0");
            $raw = chr($e | ($e === $lfnCount ? 0x40 : 0))
                . substr($chunk, 0, 10)
                . chr(0x0F) . "\0"
                . chr($checksum)
                . substr($chunk, 10, 12)
                . "\0\0"
                . substr($chunk, 22, 4);
            $this->writeSlot($target[$lfnCount - $e], $raw);
        }
        // short entry
        $raw = substr($short83, 0, 8) . substr($short83, 8, 3)
            . chr($attr) . "\0" // NT reserved
            . chr(0) // creation time (10ms units)
            . pack('v', $ftime) . pack('v', $fdate)   // creation
            . pack('v', $fdate)                        // access date
            . pack('v', ($cluster >> 16) & 0xFFFF)     // cluster high
            . pack('v', $ftime) . pack('v', $fdate)    // write time/date
            . pack('v', $cluster & 0xFFFF)              // cluster low
            . pack('V', $size);
        $this->writeSlot($target[$lfnCount], $raw);
    }

    public function mkdir(string $path): void
    {
        $this->checkWritable();
        $r = $this->resolveParent($path);
        if ($r['isRoot']) {
            throw new VolumeException('Cannot create root');
        }
        $entries = $this->parseDir($r['parentCluster']);
        if (isset($entries[$r['name']])) {
            throw new VolumeException('Already exists: ' . $path);
        }
        $clus = $this->allocCluster();
        $this->fatSet($clus, $this->fatType === 32 ? 0x0FFFFFFF : ($this->fatType === 16 ? 0xFFFF : 0x0FFF));
        $clusBytes = $this->secPerClus * $this->bytesPerSec;
        $dot = self::dirEntry83('.          ', 0x10, $clus);
        $dotdot = self::dirEntry83('..         ', 0x10, $r['parentCluster'] === 0 ? 0 : $r['parentCluster']);
        // for FAT32 root's children, ".." cluster = parent cluster; root itself special-cased
        $data = $dot . $dotdot . str_repeat("\0", $clusBytes - 64);
        $this->writeCluster($clus, $data);
        $this->createEntry($r['parentCluster'], $r['name'], true, $clus, 0);
    }

    private static function dirEntry83(string $name83, int $attr, int $cluster): string
    {
        [$ftime, $fdate] = self::dosDateTime(time());
        return substr(str_pad($name83, 11, ' '), 0, 11)
            . chr($attr) . "\0\0"
            . pack('v', $ftime) . pack('v', $fdate)
            . pack('v', $fdate)
            . pack('v', ($cluster >> 16) & 0xFFFF)
            . pack('v', $ftime) . pack('v', $fdate)
            . pack('v', $cluster & 0xFFFF)
            . pack('V', 0);
    }

    /**
     * Write a file from a string or stream. $source may be string content or
     * a readable stream resource.
     */
    public function writeFile(string $path, $source): void
    {
        $this->checkWritable();
        $r = $this->resolveParent($path);
        if ($r['isRoot']) {
            throw new VolumeException('Cannot overwrite root');
        }
        $entries = $this->parseDir($r['parentCluster']);
        $isStream = is_resource($source);
        $clusBytes = $this->secPerClus * $this->bytesPerSec;

        // collect data into clusters
        $clusters = [];
        $buf = '';
        $total = 0;
        $flushCluster = function () use (&$clusters, &$buf, $clusBytes) {
            $clusters[] = $buf . str_repeat("\0", $clusBytes - strlen($buf));
            $buf = '';
        };
        $feed = function (string $chunk) use (&$buf, &$total, $clusBytes, $flushCluster) {
            $total += strlen($chunk);
            while ($chunk !== '') {
                $space = $clusBytes - strlen($buf);
                $take = substr($chunk, 0, $space);
                $buf .= $take;
                $chunk = substr($chunk, strlen($take));
                if (strlen($buf) === $clusBytes) {
                    $flushCluster();
                }
            }
        };
        if ($isStream) {
            while (!feof($source)) {
                $chunk = fread($source, 1048576);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $feed($chunk);
            }
        } else {
            $feed((string)$source);
        }
        if ($buf !== '' || empty($clusters)) {
            $flushCluster();
        }

        // allocate + write clusters (reserve each cluster immediately so the
        // next allocCluster() doesn't hand out the same one again)
        $eoc = $this->fatType === 32 ? 0x0FFFFFFF : ($this->fatType === 16 ? 0xFFFF : 0x0FFF);
        $clusNos = [];
        foreach ($clusters as $i => $cdata) {
            $c = $this->allocCluster();
            $this->fatSet($c, $eoc); // reserve
            $clusNos[] = $c;
            $this->writeCluster($c, $cdata);
            if ($i > 0) {
                $this->fatSet($clusNos[$i - 1], $c);
            }
        }

        if (isset($entries[$r['name']])) {
            $old = $entries[$r['name']];
            if ($old['isDir']) {
                // rollback
                foreach ($clusNos as $c) {
                    $this->fatSet($c, 0);
                }
                throw new VolumeException('Is a directory: ' . $path);
            }
            // overwrite: free old chain, update entry in place
            if ($old['cluster'] >= 2) {
                $this->freeChain($old['cluster']);
            }
            $this->updateEntry($r['parentCluster'], $old, $clusNos[0], $total);
        } else {
            $this->createEntry($r['parentCluster'], $r['name'], false, $clusNos[0], $total);
        }
    }

    /** Update cluster+size (+mtime) of an existing entry in place. */
    private function updateEntry(int $parentCluster, array $entry, int $cluster, int $size): void
    {
        $slots = $this->readDirSlots($parentCluster);
        $slot = $slots[$entry['slotIdx']];
        $raw = $slot['raw'];
        [$ftime, $fdate] = self::dosDateTime(time());
        $raw = substr($raw, 0, 20)
            . pack('v', ($cluster >> 16) & 0xFFFF)
            . pack('v', $ftime) . pack('v', $fdate)
            . pack('v', $cluster & 0xFFFF)
            . pack('V', $size);
        $this->writeSlot($slot, $raw);
    }

    public function delete(string $path): void
    {
        $this->checkWritable();
        $r = $this->resolveParent($path);
        if ($r['isRoot']) {
            throw new VolumeException('Cannot delete root');
        }
        $entries = $this->parseDir($r['parentCluster']);
        if (!isset($entries[$r['name']])) {
            throw new VolumeException('Not found: ' . $path);
        }
        $e = $entries[$r['name']];
        if ($e['isDir']) {
            $children = $this->parseDir($e['cluster']);
            if (!empty($children)) {
                throw new VolumeException('Directory not empty: ' . $path);
            }
        }
        if ($e['cluster'] >= 2) {
            $this->freeChain($e['cluster']);
        }
        // mark entry + its LFN entries deleted (0xE5)
        $slots = $this->readDirSlots($r['parentCluster']);
        $idx = $e['slotIdx'];
        for ($i = $idx; $i >= 0; $i--) {
            $raw = $slots[$i]['raw'];
            if (ord($raw[11]) === 0x0F) {
                $this->writeSlot($slots[$i], "\xE5" . substr($raw, 1));
            } else {
                $this->writeSlot($slots[$i], "\xE5" . substr($raw, 1));
                break;
            }
        }
    }

    public function freeSpace(): int
    {
        $free = 0;
        $dataSecs = $this->totSec - $this->firstDataSec;
        $count = intdiv($dataSecs, $this->secPerClus);
        for ($c = 2; $c < $count + 2; $c++) {
            if ($this->fatGet($c) === 0) {
                $free++;
            }
        }
        return $free * $this->secPerClus * $this->bytesPerSec;
    }

    public function getFatType(): int { return $this->fatType; }

    /**
     * Format the volume's data area as FAT32 (pure PHP, no shell).
     * Overwrites the entire data area's filesystem structures; the volume
     * must have been created (or be opened) with 512-byte sectors.
     *
     * @param string $label volume label (max 11 chars)
     */
    public static function format(VeraCryptVolume $vol, string $label = 'CRYPTVAULT'): void
    {
        if ($vol->getSectorSize() !== 512) {
            throw new VolumeException('FAT32 format requires 512-byte volume sectors');
        }
        $totSec = $vol->getSectorCount();
        if ($totSec < 66536) {
            throw new VolumeException('Volume too small for FAT32 (need ~34 MiB)');
        }
        $bytesPerSec = 512;
        // Choose sectors per cluster: prefer 4 KiB clusters, but FAT32 needs
        // >= 65525 clusters, so shrink the cluster size for small volumes.
        $rsvdSecCnt = 32;
        $numFATs = 2;
        $secPerClus = 1;
        foreach ([8, 4, 2, 1] as $spc) {
            if (intdiv($totSec - $rsvdSecCnt, $spc) >= 66000) {
                $secPerClus = $spc;
                break;
            }
        }
        // Solve for FAT size: fatSz = ceil((clusters + 2) * 4 / 512).
        // (+2: FAT entries 0 and 1 are reserved.) Iterate to a fixed point,
        // rounding up on oscillation.
        $fatSz = 0;
        for ($i = 0; $i < 8; $i++) {
            $dataSecs = $totSec - $rsvdSecCnt - $numFATs * $fatSz;
            $clusters = intdiv($dataSecs, $secPerClus);
            $need = intdiv(($clusters + 2) * 4 + $bytesPerSec - 1, $bytesPerSec);
            if ($need <= $fatSz) {
                break;
            }
            $fatSz = $need;
        }
        $dataSecs = $totSec - $rsvdSecCnt - $numFATs * $fatSz;
        $clusters = intdiv($dataSecs, $secPerClus);
        $rootClus = 2;
        $volId = random_int(0, 0xFFFFFFFF);
        $label = strtoupper(substr($label, 0, 11));
        $label = str_pad($label, 11, ' ');

        // ---- boot sector ----
        $boot = str_repeat("\0", $bytesPerSec);
        $put = function (int $off, string $b) use (&$boot) {
            $boot = substr($boot, 0, $off) . $b . substr($boot, $off + strlen($b));
        };
        $put(0, "\xEB\x58\x90");
        $put(3, 'MSDOS5.0');
        $put(11, pack('v', $bytesPerSec));
        $put(13, chr($secPerClus));
        $put(14, pack('v', $rsvdSecCnt));
        $put(16, chr($numFATs));
        $put(17, pack('v', 0));            // root entries (FAT32: 0)
        $put(19, pack('v', 0));            // total sectors 16 (use 32)
        $put(21, chr(0xF8));               // media
        $put(22, pack('v', 0));            // FAT size 16 (use 32)
        $put(24, pack('v', 63));           // sectors per track
        $put(26, pack('v', 255));          // heads
        $put(28, pack('V', 0));            // hidden sectors
        $put(32, pack('V', $totSec));      // total sectors 32
        $put(36, pack('V', $fatSz));       // FAT size 32
        $put(40, pack('v', 0));            // ext flags
        $put(42, pack('v', 0));            // FS version
        $put(44, pack('V', $rootClus));    // root cluster
        $put(48, pack('v', 1));            // FSInfo sector
        $put(50, pack('v', 6));            // backup boot sector
        $put(62, chr(0x80));               // drive number
        $put(64, chr(0x29));               // boot signature
        $put(65, pack('V', $volId));       // volume ID
        $put(69, $label);                  // volume label
        $put(80, 'FAT32   ');              // fs type
        $put(510, "\x55\xAA");
        $vol->writeSectors(0, $boot);
        $vol->writeSectors(6, $boot);      // backup boot sector

        // ---- FSInfo sector ----
        $fsi = str_repeat("\0", $bytesPerSec);
        $putF = function (int $off, string $b) use (&$fsi) {
            $fsi = substr($fsi, 0, $off) . $b . substr($fsi, $off + strlen($b));
        };
        $putF(0, 'RRaA');
        $putF(484, 'rrAa');
        $putF(488, pack('V', $clusters - 1)); // free clusters (root takes 1)
        $putF(492, pack('V', 3));              // next free cluster hint
        $putF(510, "\x55\xAA");
        $vol->writeSectors(1, $fsi);
        $vol->writeSectors(7, $fsi);       // backup FSInfo

        // ---- FATs ----
        $fat = str_repeat("\0", $fatSz * $bytesPerSec);
        $setFat = function (int $cluster, int $val) use (&$fat) {
            $fat = substr($fat, 0, $cluster * 4) . pack('V', $val) . substr($fat, $cluster * 4 + 4);
        };
        $setFat(0, 0x0FFFFFF8); // media descriptor
        $setFat(1, 0x0FFFFFFF); // end of chain
        $setFat(2, 0x0FFFFFFF); // root dir: single cluster
        for ($f = 0; $f < $numFATs; $f++) {
            $lba = $rsvdSecCnt + $f * $fatSz;
            // write in chunks to avoid one giant string op per sector
            for ($s = 0; $s < $fatSz; $s++) {
                $vol->writeSectors($lba + $s, substr($fat, $s * $bytesPerSec, $bytesPerSec));
            }
        }

        // ---- root directory cluster (zeroed) ----
        $firstDataSec = $rsvdSecCnt + $numFATs * $fatSz;
        $zero = str_repeat("\0", $bytesPerSec);
        for ($s = 0; $s < $secPerClus; $s++) {
            $vol->writeSectors($firstDataSec + $s, $zero);
        }
    }
}
