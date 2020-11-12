<?php

declare(strict_types=1);

namespace CarrotRakko\AdvancedEncryptionStandard\Rijndael;

use DomainException;

/**
 * Round Key たちを生成するクラス
 *
 * @link https://en.wikipedia.org/wiki/AES_key_schedule
 */
final class KeySchedule
{
    /** @var int[] Round Constants の素 */
    private const RC = [
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1B,
        0x36,
    ];

    /** @var array 128bit Original Key（string） => Expanded Round Keys（string[]） */
    private static $k_128_to_w_hash = [];

    /** @var array 192bit Original Key（string） => Expanded Round Keys（string[]） */
    private static $k_192_to_w_hash = [];

    /** @var array 256bit Original Key（string） => Expanded Round Keys（string[]） */
    private static $k_256_to_w_hash = [];

    /**
     * Returns the Round Key of the specified Index
     *
     * @param string $k Original Key
     * @param int    $i Index
     * @return string Round Key
     */
    public static function getRoundKey(string $k, int $i): string
    {
        // AES-128
        if (static::isFourWord($k)) {
            if (!isset(static::$k_128_to_w_hash[$k])) {
                static::$k_128_to_w_hash[$k] = static::expand128bitsOriginalKey($k);
            }
            if (!isset(static::$k_128_to_w_hash[$k][$i])) {
                throw new DomainException('範囲外のインデックスです. $i = '. $i);
            }
            return static::$k_128_to_w_hash[$k][$i];
        }

        // AES-192
        if (static::isSixWord($k)) {
            if (!isset(static::$k_192_to_w_hash[$k])) {
                static::$k_192_to_w_hash[$k] = static::expand192bitsOriginalKey($k);
            }
            if (!isset(static::$k_192_to_w_hash[$k][$i])) {
                throw new DomainException('範囲外のインデックスです. $i = '. $i);
            }
            return static::$k_192_to_w_hash[$k][$i];
        }

        // AES-256
        if (static::isEightWord($k)) {
            if (!isset(static::$k_256_to_w_hash[$k])) {
                static::$k_256_to_w_hash[$k] = static::expand256bitsOriginalKey($k);
            }
            if (!isset(static::$k_256_to_w_hash[$k][$i])) {
                throw new DomainException('範囲外のインデックスです. $i = '. $i);
            }
            return static::$k_256_to_w_hash[$k][$i];
        }

        // Unknown Original Key Length
        throw new DomainException('Original Key must be length of either 4, 6 or 8 words. strlen($k) = ' . strlen($k));
    }

    /**
     * Expand 128 bits Original Key
     *
     * @param string $k 128 bits Original Key
     * @return string[] Round Keys, 32 bits length each
     */
    private static function expand128bitsOriginalKey(string $k): array
    {
        return array_fill(0, 4 * (10 + 1), "\0\0\0\0"); // TODO
    }

    /**
     * Expand 192 bits Original Key
     *
     * @param string $k 192 bits Original Key
     * @return string[] Round Keys, 32 bits length each
     */
    private static function expand192bitsOriginalKey(string $k): array
    {
        return array_fill(0, 4 * (12 + 1), "\0\0\0\0"); // TODO
    }

    /**
     * Expand 256 bits Original Key
     *
     * @param string $k 256 bits Original Key
     * @return string[] Round Keys, 32 bits length each
     */
    private static function expand256bitsOriginalKey(string $k): array
    {
        return array_fill(0, 4 * (14 + 1), "\0\0\0\0"); // TODO
    }

    /**
     * インデックスを指定して Round Constant を返す
     *
     * @param int $i インデックス
     * @return string 指定されたインデックスの Round Constant
     */
    private static function roundConstant(int $i): string
    {
        if (!isset(self::RC[$i])) {
            throw new DomainException('範囲外のインデックスです. $i = '. $i);
        }
        return chr(self::RC[$i]) . chr(0x00) . chr(0x00) . chr(0x00);
    }

    /**
     * ワードを RotWord する
     *
     * @param string $word RotWord されるワード
     * @return string RotWord されたワード
     */
    private static function rotWord(string $word): string
    {
        if (!static::isFourByte($word)) {
            throw new DomainException('$word は4バイトでなければなりません. strlen($word) = ' . strlen($word));
        }
        return $word[1] . $word[2] . $word[3] . $word[0];
    }

    /**
     * ワードを SubWord する
     *
     * @param string $word SubWord されるワード
     * @return string SubWord されたワード
     */
    private static function subWord(string $word): string
    {
        if (!static::isFourByte($word)) {
            throw new DomainException('$word は4バイトでなければなりません. strlen($word) = ' . strlen($word));
        }
        return SBox::forward($word[0]) . SBox::forward($word[1]) . SBox::forward($word[2]) . SBox::forward($word[3]);
    }

    /**
     * 文字列が4バイトか？
     *
     * @param string $string 文字列
     * @return bool 4バイトか？
     */
    private static function isFourByte(string $string): bool
    {
        return strlen($string) === 4;
    }

    /**
     * 文字列が4ワードか？
     *
     * @param string $string 文字列
     * @return bool 4ワードか？
     */
    private static function isFourWord(string $string): bool
    {
        return strlen($string) === 4 * 4;
    }

    /**
     * 文字列が6ワードか？
     *
     * @param string $string 文字列
     * @return bool 6ワードか？
     */
    private static function isSixWord(string $string): bool
    {
        return strlen($string) === 4 * 6;
    }

    /**
     * 文字列が8ワードか？
     *
     * @param string $string 文字列
     * @return bool 8ワードか？
     */
    private static function isEightWord(string $string): bool
    {
        return strlen($string) === 4 * 8;
    }
}
