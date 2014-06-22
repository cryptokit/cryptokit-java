package org.cryptokit.core;

import java.nio.charset.Charset;

public class CryptoConstants {
    public static final String PBKDF2_HASH_ALGORITHM = "PBKDF2WithHmacSHA1";

    public static final Charset CHARSET = Charset.forName("UTF-8");

    public static final char SEGMENT_DELIMITER = '.';
    public static final String SEGMENT_DELIMITER_PATTERN = "\\.";
}
