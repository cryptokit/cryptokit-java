package org.cryptokit.password;

public class PasswordTokenSpec {
    public static final int PASSWORD_SALT_BYTE_SIZE = 32;
    public static final int PASSWORD_HASH_BYTE_SIZE = 32;
    public static final int PASSWORD_HASH_DEFAULT_ITERATIONS = 5000;

    public static final String PASSWORD_TOKEN_HEADER = "ck_p1";

    public static final int PASSWORD_SEGMENT_HEADER = 0;
    public static final int PASSWORD_SEGMENT_ITERATIONS = 1;
    public static final int PASSWORD_SEGMENT_SALT = 2;
    public static final int PASSWORD_SEGMENT_HASH = 3;
    public static final int PASSWORD_NUM_SEGMENTS = 4;
}
