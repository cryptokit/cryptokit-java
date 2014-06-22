package org.cryptokit.core;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Crypto {

    /**
     * Password-Based Key Derivation Function 2 (PBKDF2) implementation
     * <p/>
     * You should be using the high-level PasswordHasher class to hash
     * passwords for storage.
     *
     * @param password            Plain text password
     * @param salt                Bytes to salt the password with
     * @param iterations          Number of hash iterations to compute
     * @param desiredHashByteSize Desired size of the resulting hash, in bytes
     * @return PBKDF2 Hashed bytes
     * @throws NoSuchAlgorithmException The Java crypto provider doesn't support the PBKDF2 algorithm
     * @throws InvalidKeySpecException  The internal key spec does not match the PKBDF2 implementation
     */
    public static byte[] pbkdf2(final String password, final byte[] salt, final int iterations, final int desiredHashByteSize)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, desiredHashByteSize * Byte.SIZE);
        final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(CryptoConstants.PBKDF2_HASH_ALGORITHM);
        final SecretKey secretKey = keyFactory.generateSecret(spec);
        final byte[] pbkdf2Bytes = secretKey.getEncoded();

        return pbkdf2Bytes;
    }

    /**
     * Generates a secure random salt of desired size
     *
     * @param saltByteSize Size of the salt to generate, in bytes
     * @return Secure random bytes suitable for use as salt
     */
    public static byte[] generateSalt(final int saltByteSize) {
        final SecureRandom random = new SecureRandom();
        final byte[] saltBytes = new byte[saltByteSize];
        random.nextBytes(saltBytes);

        return saltBytes;
    }
}
