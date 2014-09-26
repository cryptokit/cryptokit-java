package org.cryptokit.core;

import java.nio.charset.Charset;

public class CryptoConstants {
    public static final String PBKDF2_HASH_ALGORITHM = "PBKDF2WithHmacSHA1";

    public static final int AES_BLOCK_SIZE_BYTES = 16;
    public static final String AES_MODE = "CTR";
    public static final String AES_PADDING = "PKCS5Padding";
    public static final String AES_CIPHER_ALGORITHM = String.format("AES/%s/%s", AES_MODE, AES_PADDING);

    public static final Charset CHARSET = Charset.forName("UTF-8");

    public static final char SEGMENT_DELIMITER = '.';
    public static final String SEGMENT_DELIMITER_PATTERN = "\\.";
}
