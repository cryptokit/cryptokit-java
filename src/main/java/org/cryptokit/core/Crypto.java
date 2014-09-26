package org.cryptokit.core;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class Crypto {

    public static byte[] aesEncrypt(final SecretKey secretKey, final byte[] iv, final String plaintext)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.AES_CIPHER_ALGORITHM);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        final byte[] cipherBytes = aesCipher.doFinal(StringUtils.getStringBytes(plaintext));

        return cipherBytes;
    }

    public static byte[] aesDecrypt(final SecretKey secretKey, final byte[] iv, byte[] cipherBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.AES_CIPHER_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        final byte[] decryptedBytes = aesCipher.doFinal(cipherBytes);

        return decryptedBytes;
    }

    /**
     * Password-based key derivation function (PBKDF2) implementation
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
     * Generate secure random bytes
     *
     * @param numBytes Number of random bytes to generate
     * @return Random bytes suitable for example as salt or initialization vector
     */
    public static byte[] generateRandomBytes(final int numBytes) {
        final SecureRandom random = new SecureRandom();
        final byte[] saltBytes = new byte[numBytes];
        random.nextBytes(saltBytes);

        return saltBytes;
    }
}
