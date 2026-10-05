<?php
declare(strict_types=1);

namespace OCA\CryptVault\Crypto;

/**
 * VeraCrypt file-hosted volume handling (AES-256-XTS + PBKDF2 only).
 *
 * Format (public VeraCrypt volume format specification):
 *   offset 0,      64 bytes: salt (plaintext)
 *   offset 64,    448 bytes: header, AES-XTS encrypted, data-unit 0,
 *                            key = PBKDF2-HMAC-PRF(password, salt, iter, 64)
 *   offset 65536, 512 bytes: hidden-volume header slot
 *   offset 131072:           start of encrypted data area (typical)
 *
 * Decrypted 448-byte header (all integers big-endian):
 *   0   : "VERA" magic (4)
 *   4   : header version u16, 6: min version u16
 *   8   : CRC32 of bytes [192..448) u32
 *   12  : volume creation time u64, 20: header creation time u64
 *   28  : hidden volume size u64
 *   36  : volume size u64
 *   44  : encrypted area start u64
 *   52  : encrypted area length u64
 *   60  : flags u32
 *   64  : sector size u16
 *   188 : CRC32 of bytes [0..188) u32
 *   192 : master key material (256); AES-256-XTS uses [192..256)
 */
class VeraCryptVolume
{
    public const SALT_LEN = 64;
    public const HEADER_ENC_LEN = 448;
    public const HEADER_TOTAL_LEN = 512;
    public const HIDDEN_HEADER_OFFSET = 65536;
    public const AREA_RESERVED = 131072; // typical header-area size

    /** PRF => [default iterations, PIM formula] (non-system volumes). */
    private const PRFS = [
        'sha512'    => [500000, 'std'],
        'sha256'    => [500000, 'std'],
        'whirlpool' => [500000, 'std'],
        'ripemd160' => [655331, 'ripemd'],
    ];

    /** Legacy TrueCrypt iteration fallbacks (magic "TRUE"). */
    private const LEGACY_ITERS = [1000, 2000];

    private $fh;
    private string $path;
    private string $masterKey; // 64-byte XTS key
    private string $headerDec; // 448-byte decrypted primary header (for password changes)
    private string $headerKey = ''; // 64-byte PBKDF2 header key (kept only to allow caching)
    private int $headerOffset; // file offset of the opened header (0 or 65536)
    private int $areaStart;
    private int $areaLength;
    private int $sectorSize;
    private int $volumeSize;
    private int $flags;
    private int $hiddenSize;
    private bool $readOnly;

    private function __construct() {}

    /**
     * Open a volume file. Tries every supported PRF/iteration combo and both
     * the primary header (offset 0) and, when $tryHidden, the hidden header
     * (offset 65536).
     *
     * @throws VolumeException on wrong password / unsupported volume
     */
    public static function open(string $path, string $password, int $pim = 0, bool $tryHidden = false, bool $readOnly = false): self
    {
        if ($password === '') {
            throw new VolumeException('Empty password');
        }
        $fh = @fopen($path, $readOnly ? 'rb' : 'c+b');
        if ($fh === false) {
            throw new VolumeException('Cannot open volume file');
        }
        $size = fstat($fh)['size'];
        if ($size < self::HEADER_TOTAL_LEN) {
            fclose($fh);
            throw new VolumeException('File too small to be a VeraCrypt volume');
        }

        $offsets = $tryHidden ? [self::HIDDEN_HEADER_OFFSET, 0] : [0, self::HIDDEN_HEADER_OFFSET];
        $lastError = 'Unsupported volume (cipher, KDF, or filesystem settings this app cannot read)';
        foreach ($offsets as $off) {
            if ($off + self::HEADER_TOTAL_LEN > $size) {
                continue;
            }
            fseek($fh, $off);
            $hdr = fread($fh, self::HEADER_TOTAL_LEN);
            if ($hdr === false || strlen($hdr) !== self::HEADER_TOTAL_LEN) {
                continue;
            }
            $vol = self::tryHeader($fh, $path, $off, $hdr, $password, $pim, $readOnly, $size);
            if ($vol !== null) {
                return $vol;
            }
        }
        fclose($fh);
        throw new VolumeException('Wrong password, or this volume uses settings CryptVault cannot open (see Help).');
    }

    private static function tryHeader($fh, string $path, int $off, string $hdr, string $password, int $pim, bool $readOnly, int $size): ?self
    {
        $salt = substr($hdr, 0, self::SALT_LEN);
        $enc = substr($hdr, self::SALT_LEN, self::HEADER_ENC_LEN);

        $attempts = [];
        foreach (self::PRFS as $prf => [$defIter, $kind]) {
            $iter = $pim > 0
                ? ($kind === 'ripemd' ? $pim * 2048 : 15000 + $pim * 1000)
                : $defIter;
            $attempts[] = [$prf, $iter, 'VERA'];
        }
        // Legacy TrueCrypt fallbacks (cheap: only after the VeraCrypt set fails)
        foreach (self::PRFS as $prf => $_) {
            foreach (self::LEGACY_ITERS as $iter) {
                $attempts[] = [$prf, $iter, 'TRUE'];
            }
        }

        foreach ($attempts as [$prf, $iter, $wantMagic]) {
            $key = @hash_pbkdf2($prf, $password, $salt, $iter, 64, true);
            if ($key === false || strlen($key) !== 64) {
                continue;
            }
            try {
                $dec = Xts::decrypt($enc, $key, 0);
            } catch (\Throwable) {
                continue;
            }
            $magic = substr($dec, 0, 4);
            if ($magic !== 'VERA' && $magic !== $wantMagic) {
                continue;
            }
            if (!self::crcOk($dec, 8, substr($dec, 192, 256))) {
                continue;
            }
            if (!self::crcOk($dec, 188, substr($dec, 0, 188))) {
                continue;
            }
            // Header is valid.
            return self::buildFromDecrypted($fh, $path, $off, $dec, $readOnly, $key);
        }
        return null;
    }

    /**
     * Re-open a volume using a previously derived header key (skips PBKDF2).
     * The header key must be the 64-byte PBKDF2 output for the header at
     * $headerOffset, as cached from an earlier successful open().
     *
     * @throws VolumeException if the key no longer decrypts the header
     */
    public static function openWithHeaderKey(string $path, string $headerKey, int $headerOffset, bool $readOnly = false): self
    {
        if (strlen($headerKey) !== 64) {
            throw new VolumeException('Bad cached key');
        }
        $fh = @fopen($path, $readOnly ? 'rb' : 'c+b');
        if ($fh === false) {
            throw new VolumeException('Cannot open volume file');
        }
        $size = fstat($fh)['size'];
        if ($headerOffset + self::HEADER_TOTAL_LEN > $size) {
            fclose($fh);
            throw new VolumeException('Volume changed (header moved)');
        }
        fseek($fh, $headerOffset);
        $hdr = fread($fh, self::HEADER_TOTAL_LEN);
        if ($hdr === false || strlen($hdr) !== self::HEADER_TOTAL_LEN) {
            fclose($fh);
            throw new VolumeException('Cannot read volume header');
        }
        $enc = substr($hdr, self::SALT_LEN, self::HEADER_ENC_LEN);
        try {
            $dec = Xts::decrypt($enc, $headerKey, 0);
        } catch (\Throwable) {
            fclose($fh);
            throw new VolumeException('Cached key rejected');
        }
        if (substr($dec, 0, 4) !== 'VERA'
            || !self::crcOk($dec, 8, substr($dec, 192, 256))
            || !self::crcOk($dec, 188, substr($dec, 0, 188))) {
            fclose($fh);
            throw new VolumeException('Cached key rejected');
        }
        return self::buildFromDecrypted($fh, $path, $headerOffset, $dec, $readOnly);
    }

    /** Build an open volume from an already-decrypted, validated header. */
    private static function buildFromDecrypted($fh, string $path, int $off, string $dec, bool $readOnly, string $headerKey = ''): self
    {
            $vol = new self();
            $vol->fh = $fh;
            $vol->path = $path;
            $vol->masterKey = substr($dec, 192, 64);
            $vol->headerDec = $dec;
            $vol->headerOffset = $off;
            $vol->hiddenSize = self::u64(substr($dec, 28, 8));
            $vol->volumeSize = self::u64(substr($dec, 36, 8));
            $vol->areaStart = self::u64(substr($dec, 44, 8));
            $vol->areaLength = self::u64(substr($dec, 52, 8));
            $vol->flags = self::u32(substr($dec, 60, 4));
            $vol->sectorSize = self::u32(substr($dec, 64, 4));
            $vol->readOnly = $readOnly;
            $vol->headerKey = $headerKey;
            if ($vol->sectorSize < 512 || $vol->sectorSize > 4096 || ($vol->sectorSize % 512) !== 0) {
                // Unusual but not fatal; clamp to 512 for data-unit math
                $vol->sectorSize = 512;
            }
            return $vol;
    }

    private static function crcOk(string $dec, int $crcOff, string $data): bool
    {
        $stored = self::u32(substr($dec, $crcOff, 4));
        return $stored === (crc32($data) & 0xFFFFFFFF);
    }

    private static function u16(string $b): int { return unpack('n', $b)[1]; }
    private static function u32(string $b): int { return unpack('N', $b)[1]; }
    private static function u64(string $b): int
    {
        $v = unpack('J', $b)[1];
        return $v < 0 ? 0 : $v; // guard against overflow weirdness
    }

    // ---- sector I/O ------------------------------------------------------

    /** XTS data-unit number for logical sector $lba (0-based in data area). */
    public function unitForLba(int $lba): int
    {
        // Anchored to the physical start of the encrypted area (aes-xts-plain64 style).
        return intdiv($this->areaStart + $lba * $this->sectorSize, 512);
    }

    /** Read $count sectors starting at $lba (decrypted). */
    public function readSectors(int $lba, int $count = 1): string
    {
        $out = '';
        fseek($this->fh, $this->areaStart + $lba * $this->sectorSize);
        $raw = fread($this->fh, $count * $this->sectorSize);
        if ($raw === false || strlen($raw) !== $count * $this->sectorSize) {
            throw new VolumeException('Read past end of volume');
        }
        for ($i = 0; $i < $count; $i++) {
            $out .= Xts::decrypt(substr($raw, $i * $this->sectorSize, $this->sectorSize), $this->masterKey, $this->unitForLba($lba + $i));
        }
        return $out;
    }

    /** Write $count sectors starting at $lba (encrypts). */
    public function writeSectors(int $lba, string $data): void
    {
        if ($this->readOnly) {
            throw new VolumeException('Volume is mounted read-only');
        }
        $ss = $this->sectorSize;
        if ((strlen($data) % $ss) !== 0) {
            throw new \InvalidArgumentException('Data must be a whole number of sectors');
        }
        $count = strlen($data) / $ss;
        $raw = '';
        for ($i = 0; $i < $count; $i++) {
            $raw .= Xts::encrypt(substr($data, $i * $ss, $ss), $this->masterKey, $this->unitForLba($lba + $i));
        }
        fseek($this->fh, $this->areaStart + $lba * $this->sectorSize);
        $w = fwrite($this->fh, $raw);
        if ($w !== strlen($raw)) {
            throw new VolumeException('Short write to volume');
        }
        fflush($this->fh);
    }

    public function getSectorSize(): int { return $this->sectorSize; }
    public function getSectorCount(): int { return intdiv($this->areaLength, $this->sectorSize); }
    public function getVolumeSize(): int { return $this->volumeSize; }
    public function hasHiddenVolume(): bool { return $this->hiddenSize > 0; }
    public function isReadOnly(): bool { return $this->readOnly; }
    public function getPath(): string { return $this->path; }

    /**
     * The 64-byte derived header key for this open volume ('' if opened via
     * openWithHeaderKey). Callers that cache it must treat it as a secret
     * equivalent to the password and wipe it when done.
     */
    public function getHeaderKey(): string { return $this->headerKey; }

    /** Header offset (0 or 65536) — needed alongside the header key to re-open. */
    public function getHeaderOffset(): int { return $this->headerOffset; }

    public function close(): void
    {
        if (is_resource($this->fh)) {
            fclose($this->fh);
        }
        // wipe key material
        $this->masterKey = str_repeat("\0", 64);
        $this->headerKey = str_repeat("\0", 64);
    }

    public function __destruct() { $this->close(); }

    // ---- volume creation --------------------------------------------------

    /**
     * Create a new AES-256-XTS + PBKDF2-SHA-512 volume file and return an
     * open handle to it (data area zeroed, header written).
     */
    public static function create(string $path, string $password, int $dataBytes, int $sectorSize = 512): self
    {
        if ($password === '') {
            throw new VolumeException('Empty password');
        }
        if ($dataBytes < 1024 * 1024) {
            throw new VolumeException('Volume too small (min 1 MiB of data area)');
        }
        $fh = @fopen($path, 'w+b');
        if ($fh === false) {
            throw new VolumeException('Cannot create volume file');
        }
        $salt = random_bytes(self::SALT_LEN);
        $masterKeyArea = random_bytes(256);
        $masterKey = substr($masterKeyArea, 0, 64);

        $areaStart = self::AREA_RESERVED;
        $volumeSize = $areaStart + $dataBytes;
        // Keep a backup header slot at the end like VeraCrypt does.
        $totalSize = $volumeSize + self::AREA_RESERVED;

        $dec = str_repeat("\0", self::HEADER_ENC_LEN);
        $put = function (int $off, string $bytes) use (&$dec) {
            $dec = substr($dec, 0, $off) . $bytes . substr($dec, $off + strlen($bytes));
        };
        $put(0, 'VERA');
        $put(4, pack('n', 5));          // header version
        $put(6, pack('n', 0x0100));     // min program version
        $now = time();
        $put(12, pack('J', $now));      // volume creation time
        $put(20, pack('J', $now));      // header creation time
        $put(28, pack('J', 0));         // hidden volume size
        $put(36, pack('J', $volumeSize));
        $put(44, pack('J', $areaStart));
        $put(52, pack('J', $dataBytes));
        $put(60, pack('N', 0));         // flags
        $put(64, pack('N', $sectorSize));
        $put(192, $masterKeyArea);
        $put(8, pack('N', crc32(substr($dec, 192, 256)) & 0xFFFFFFFF));
        $put(188, pack('N', crc32(substr($dec, 0, 188)) & 0xFFFFFFFF));

        $headerKey = hash_pbkdf2('sha512', $password, $salt, 500000, 64, true);
        $encHeader = Xts::encrypt($dec, $headerKey, 0);

        // Layout: primary header @0, hidden slot @65536 (random fill like VC),
        // backup header area at the very end of the file.
        $area = random_bytes(self::AREA_RESERVED);
        $area = $salt . $encHeader . substr($area, self::HEADER_TOTAL_LEN);
        // backup header at the end
        fseek($fh, 0);
        fwrite($fh, $area);
        // zero the data area (sparse-friendly: write in chunks)
        fseek($fh, $areaStart);
        $zero = str_repeat("\0", 1024 * 1024);
        $remaining = $dataBytes;
        while ($remaining > 0) {
            $chunk = $remaining > strlen($zero) ? $zero : substr($zero, 0, $remaining);
            fwrite($fh, $chunk);
            $remaining -= strlen($chunk);
        }
        // backup header area
        fseek($fh, $totalSize - self::AREA_RESERVED);
        fwrite($fh, $area);
        fflush($fh);

        $vol = new self();
        $vol->fh = $fh;
        $vol->path = $path;
        $vol->masterKey = $masterKey;
        $vol->headerDec = $dec;
        $vol->headerOffset = 0;
        $vol->areaStart = $areaStart;
        $vol->areaLength = $dataBytes;
        $vol->sectorSize = $sectorSize;
        $vol->volumeSize = $volumeSize;
        $vol->flags = 0;
        $vol->hiddenSize = 0;
        $vol->readOnly = false;
        return $vol;
    }

    /**
     * Change the volume password: re-encrypt the header with a new salt.
     * Data is untouched (fast). Updates primary and backup headers when this
     * is the primary header; a hidden-volume header updates its own slots.
     */
    public function changePassword(string $newPassword, int $pim = 0): void
    {
        if ($this->readOnly) {
            throw new VolumeException('Volume is mounted read-only');
        }
        if ($newPassword === '') {
            throw new VolumeException('Empty password');
        }
        $dec = $this->headerDec;
        // refresh header creation time
        $dec = substr($dec, 0, 20) . pack('J', time()) . substr($dec, 28);
        // recompute CRCs (fields may have changed)
        $dec = substr($dec, 0, 8) . pack('N', crc32(substr($dec, 192, 256)) & 0xFFFFFFFF) . substr($dec, 12);
        $dec = substr($dec, 0, 188) . pack('N', crc32(substr($dec, 0, 188)) & 0xFFFFFFFF) . substr($dec, 192);

        $salt = random_bytes(self::SALT_LEN);
        $iter = $pim > 0 ? 15000 + $pim * 1000 : 500000;
        $headerKey = hash_pbkdf2('sha512', $newPassword, $salt, $iter, 64, true);
        $encHeader = Xts::encrypt($dec, $headerKey, 0);
        $full = $salt . $encHeader;

        $slots = [$this->headerOffset];
        // Also refresh the backup header slot (mirrors VeraCrypt behavior).
        if ($this->headerOffset === 0) {
            $slots[] = $this->volumeSize; // backup primary at end of volume area
        } elseif ($this->headerOffset === self::HIDDEN_HEADER_OFFSET) {
            $slots[] = $this->volumeSize + self::HIDDEN_HEADER_OFFSET;
        }
        $size = fstat($this->fh)['size'];
        foreach ($slots as $slot) {
            if ($slot + self::HEADER_TOTAL_LEN <= $size) {
                fseek($this->fh, $slot);
                fwrite($this->fh, $full);
            }
        }
        fflush($this->fh);
        $this->headerDec = $dec;
        // wipe
        $headerKey = str_repeat("\0", 64);
    }

    /**
     * Back up the volume header (512 bytes: salt + encrypted header) to a file.
     * VeraCrypt-compatible: restore with desktop VeraCrypt's "Restore Volume Header".
     */
    public function backupHeader(string $destPath): void
    {
        fseek($this->fh, $this->headerOffset);
        $hdr = fread($this->fh, self::HEADER_TOTAL_LEN);
        if ($hdr === false || strlen($hdr) !== self::HEADER_TOTAL_LEN) {
            throw new VolumeException('Cannot read header for backup');
        }
        if (@file_put_contents($destPath, $hdr) !== self::HEADER_TOTAL_LEN) {
            throw new VolumeException('Cannot write header backup file');
        }
    }
}
