package org.cryptokit.core;

import org.apache.commons.codec.binary.Base64;

public class StringUtils {

    public static byte[] getStringBytes(final String inputString) {
        final byte[] stringBytes = inputString.getBytes(CryptoConstants.CHARSET);

        return stringBytes;
    }

    public static boolean isNullOrEmpty(String string) {
        return string == null || string.trim().isEmpty();
    }

    public static String base64Encode(final String inputString) {
        final byte[] stringBytes = StringUtils.getStringBytes(inputString);
        final String base64String = Base64.encodeBase64URLSafeString(stringBytes);

        return base64String;
    }

    public static String base64Encode(final byte[] inputBytes) {
        final String base64String = Base64.encodeBase64URLSafeString(inputBytes);

        return base64String;
    }

    public static String base64Decode(final String inputBase64String) {
        final byte[] bytes = Base64.decodeBase64(inputBase64String);
        final String decodedString = new String(bytes, CryptoConstants.CHARSET);

        return decodedString;
    }

    public static String base64Decode(final byte[] inputBase64Bytes) {
        final byte[] bytes = Base64.decodeBase64(inputBase64Bytes);
        final String decodedString = new String(bytes, CryptoConstants.CHARSET);

        return decodedString;
    }

    public static byte[] base64DecodeBytes(final String inputBase64String) {
        final byte[] decodedBytes = Base64.decodeBase64(inputBase64String);

        return decodedBytes;
    }

    public static byte[] base64DecodeBytes(final byte[] inputBase64Bytes) {
        final byte[] decodedBytes = Base64.decodeBase64(inputBase64Bytes);

        return decodedBytes;
    }
}
