package org.cryptokit.key;

import org.cryptokit.core.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyLoader {

    public static SecretKey SymmetricKeyFromString(final String secretKeyString) {
        SecretKeySpec keySpec = new SecretKeySpec(StringUtils.getStringBytes(secretKeyString), KeySpec.SYMMETRIC_CIPHER);

        return keySpec;
    }

    public static SecretKey SymmetricKey(final byte[] keyBytes) {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, KeySpec.SYMMETRIC_CIPHER);

        return keySpec;
    }

}
