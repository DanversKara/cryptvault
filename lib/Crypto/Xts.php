<?php
declare(strict_types=1);

namespace OCA\CryptVault\Crypto;

/**
 * XTS-AES-256 (IEEE 1619) built on OpenSSL.
 *
 * Primary path uses OpenSSL's native aes-256-xts (fast, constant-time).
 * A pure-PHP fallback built from AES-ECB is used only if the cipher is
 * unavailable. Both paths are cross-checked by the test harness.
 */
final class Xts
{
    private static ?bool $hasNative = null;

    public static function hasNative(): bool
    {
        if (self::$hasNative === null) {
            self::$hasNative = in_array('aes-256-xts', openssl_get_cipher_methods(), true);
        }
        return self::$hasNative;
    }

    /** 128-bit little-endian encoding of a data-unit number. */
    public static function le128(int $n): string
    {
        // pack as two LE 64-bit words; $n fits in 64 bits for our volumes
        return pack('P', $n) . "\0\0\0\0\0\0\0\0";
    }

    /**
     * Decrypt $data (length multiple of 16) with AES-256-XTS.
     * $key must be 64 bytes (K1 || K2). $unit is the XTS data-unit number.
     */
    public static function decrypt(string $data, string $key, int $unit): string
    {
        if ((strlen($data) % 16) !== 0) {
            throw new \InvalidArgumentException('XTS data length must be a multiple of 16');
        }
        if (strlen($key) !== 64) {
            throw new \InvalidArgumentException('XTS-AES-256 key must be 64 bytes');
        }
        if (self::hasNative()) {
            $out = openssl_decrypt($data, 'aes-256-xts', $key, OPENSSL_RAW_DATA, self::le128($unit));
            if ($out !== false) {
                return $out;
            }
            // fall through to manual path on failure
        }
        return self::decryptManual($data, $key, $unit);
    }

    /**
     * Encrypt $data (length multiple of 16) with AES-256-XTS.
     */
    public static function encrypt(string $data, string $key, int $unit): string
    {
        if ((strlen($data) % 16) !== 0) {
            throw new \InvalidArgumentException('XTS data length must be a multiple of 16');
        }
        if (strlen($key) !== 64) {
            throw new \InvalidArgumentException('XTS-AES-256 key must be 64 bytes');
        }
        if (self::hasNative()) {
            $out = openssl_encrypt($data, 'aes-256-xts', $key, OPENSSL_RAW_DATA, self::le128($unit));
            if ($out !== false) {
                return $out;
            }
        }
        return self::encryptManual($data, $key, $unit);
    }

    /**
     * Manual XTS from AES-ECB single-block ops.
     * T_0 = AES_K2(tweak); T_j = T_0 * alpha^j in GF(2^128);
     * C_j = AES_K1(P_j XOR T_j) XOR T_j.
     */
    private static function cryptManual(string $data, string $key, int $unit, bool $doEncrypt): string
    {
        $k1 = substr($key, 0, 32);
        $k2 = substr($key, 32, 32);
        $tweak = openssl_encrypt(self::le128($unit), 'aes-256-ecb', $k2, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($tweak === false || strlen($tweak) !== 16) {
            throw new \RuntimeException('ECB tweak encryption failed');
        }
        $out = '';
        $n = strlen($data) >> 4;
        for ($j = 0; $j < $n; $j++) {
            $blk = substr($data, $j << 4, 16);
            $x = $blk ^ $tweak;
            $y = $doEncrypt
                ? openssl_encrypt($x, 'aes-256-ecb', $k1, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING)
                : openssl_decrypt($x, 'aes-256-ecb', $k1, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
            if ($y === false) {
                throw new \RuntimeException('ECB block crypt failed');
            }
            $out .= $y ^ $tweak;
            $tweak = self::mulAlpha($tweak);
        }
        return $out;
    }

    public static function decryptManual(string $data, string $key, int $unit): string
    {
        return self::cryptManual($data, $key, $unit, false);
    }

    public static function encryptManual(string $data, string $key, int $unit): string
    {
        return self::cryptManual($data, $key, $unit, true);
    }

    /**
     * Multiply a 16-byte tweak by alpha in GF(2^128),
     * reduction polynomial x^128 + x^7 + x^2 + x + 1.
     * Byte 0 is the least-significant byte (matches OpenSSL/kernel XTS).
     */
    public static function mulAlpha(string $t): string
    {
        $bytes = array_values(unpack('C16', $t));
        $carry = 0;
        for ($i = 0; $i < 16; $i++) {
            $b = $bytes[$i];
            $bytes[$i] = (($b << 1) | $carry) & 0xFF;
            $carry = ($b >> 7) & 1;
        }
        if ($carry) {
            $bytes[0] ^= 0x87;
        }
        return pack('C16', ...$bytes);
    }
}
