package org.cryptokit.crypto;

public class CryptoTokenSpec {
    public static final String SYMMETRIC_CRYPTO_TOKEN_HEADER = "ck_sc1";
    public static final String ASYMMETRIC_CRYPTO_TOKEN_HEADER = "ck_ac1";

    public static final int CRYPTO_SEGMENT_HEADER = 0;
    public static final int CRYPTO_SEGMENT_IV = 1;
    public static final int CRYPTO_SEGMENT_CIPHER = 2;
    public static final int CRYPTO_NUM_SEGMENTS = 3;
}
