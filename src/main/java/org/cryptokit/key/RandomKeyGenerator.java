package org.cryptokit.key;

import org.cryptokit.exception.PreconditionFailedException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RandomKeyGenerator {

    public static SecretKey generateSymmetricKey() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance(KeySpec.SYMMETRIC_CIPHER);
        } catch (NoSuchAlgorithmException e) {
            throw new PreconditionFailedException("System crypto provider does not support cipher " + KeySpec.SYMMETRIC_CIPHER, e);
        }
        keyGenerator.init(KeySpec.SYMMETRIC_KEY_SIZE_BYTES * Byte.SIZE);

        final SecretKey secretKey = keyGenerator.generateKey();

        return secretKey;
    }

    public static KeyPair generateAsymmetricKeyPair() {
        KeyPairGenerator keyPairGenerator;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(KeySpec.ASYMMETRIC_CIPHER);
        } catch (NoSuchAlgorithmException e) {
            throw new PreconditionFailedException("System crypto provider does not support cipher " + KeySpec.ASYMMETRIC_CIPHER, e);
        }
        keyPairGenerator.initialize(KeySpec.ASYMMETRIC_KEY_SIZE_BYTES * Byte.SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return keyPair;
    }
}
