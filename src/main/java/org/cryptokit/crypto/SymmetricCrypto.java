package org.cryptokit.crypto;

import org.cryptokit.core.Crypto;
import org.cryptokit.core.CryptoConstants;
import org.cryptokit.core.StringUtils;
import org.cryptokit.exception.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.cryptokit.crypto.CryptoTokenSpec.*;

public class SymmetricCrypto {

    private final SecretKey mSecretKey;

    public SymmetricCrypto(final SecretKey secretKey) {
        if (secretKey == null) {
            throw new InvalidInputException("Secret key cannot be null");
        }

        mSecretKey = secretKey;
    }

    public String encrypt(final String plainText) {
        if (StringUtils.isNullOrEmpty(plainText)) {
            throw new InvalidInputException("Text to encrypt cannot be null or empty");
        }

        final byte[] ivBytes = Crypto.generateRandomBytes(CryptoConstants.AES_BLOCK_SIZE_BYTES);

        final byte[] cipherBytes = encrypt(mSecretKey, ivBytes, plainText);
        final String cryptoToken = encodeCryptoToken(ivBytes, cipherBytes);

        return cryptoToken;
    }

    public String decrypt(final String cryptoToken) {
        if (StringUtils.isNullOrEmpty(cryptoToken)) {
            throw new InvalidInputException("Crypto token to decrypt cannot be null or empty");
        }

        final String[] segments = decodeCryptoToken(cryptoToken);
        final String base64Iv = segments[CRYPTO_SEGMENT_IV];
        final String base64Cipher = segments[CRYPTO_SEGMENT_CIPHER];
        final byte[] ivBytes = StringUtils.base64DecodeBytes(base64Iv);
        final byte[] cipherBytes = StringUtils.base64DecodeBytes(base64Cipher);

        final byte[] decryptedBytes = decrypt(mSecretKey, ivBytes, cipherBytes);
        final String plainText = new String(decryptedBytes, CryptoConstants.CHARSET);

        return plainText;
    }

    private byte[] encrypt(SecretKey secretKey, final byte[] ivBytes, final String plainText) {
        final byte[] cipherBytes;

        try {
            cipherBytes = Crypto.aesEncrypt(secretKey, ivBytes, plainText);
        } catch (NoSuchPaddingException e) {
            throw new PreconditionFailedException("System crypto provider does not support AES padding type " + CryptoConstants.AES_PADDING, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PreconditionFailedException("System crypto provider does not support algorithm " + CryptoConstants.AES_CIPHER_ALGORITHM, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new PreconditionFailedException("System crypto provider does not support the request algorithm parameter", e);
        } catch (InvalidKeyException e) {
            throw new PreconditionFailedException("The provided key does not appear to be a valid " + secretKey.getAlgorithm() + " key", e);
        } catch (BadPaddingException e) {
            throw new ImplementationFailedException("Bad padding (oops, please file a bug)", e);
        } catch (IllegalBlockSizeException e) {
            throw new ImplementationFailedException("Illegal block size (oops, please file a bug)", e);
        }

        return cipherBytes;
    }

    private byte[] decrypt(SecretKey secretKey, final byte[] ivBytes, final byte[] cipherBytes) {
        byte[] decryptedBytes;

        try {
            decryptedBytes = Crypto.aesDecrypt(secretKey, ivBytes, cipherBytes);
        } catch (NoSuchPaddingException e) {
            throw new PreconditionFailedException("System crypto provider does not support AES padding type " + CryptoConstants.AES_PADDING, e);
        } catch (NoSuchAlgorithmException e) {
            throw new PreconditionFailedException("System crypto provider does not support the algorithm " + CryptoConstants.AES_CIPHER_ALGORITHM, e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new PreconditionFailedException("System crypto provider does not support the request algorithm parameter", e);
        } catch (InvalidKeyException e) {
            throw new PreconditionFailedException("The provided key does not appear to be a valid " + secretKey.getAlgorithm() + " key", e);
        } catch (BadPaddingException e) {
            throw new DecryptionFailedException("Crypto token does not decrypt with the provided key", e);
        } catch (IllegalBlockSizeException e) {
            throw new ImplementationFailedException("Illegal block size (oops, please file a bug)", e);
        }

        return decryptedBytes;
    }

    private String encodeCryptoToken(final byte[] iv, final byte[] cipherBytes) {
        final String base64Iv = StringUtils.base64Encode(iv);
        final String base64cipher = StringUtils.base64Encode(cipherBytes);
        final String cryptoToken =
                SYMMETRIC_CRYPTO_TOKEN_HEADER + CryptoConstants.SEGMENT_DELIMITER +
                        base64Iv + CryptoConstants.SEGMENT_DELIMITER +
                        base64cipher;

        return cryptoToken;
    }

    // Decode the crypto token into its constituent parts
    private static String[] decodeCryptoToken(final String cryptoToken) {
        final String[] segments = cryptoToken.split(CryptoConstants.SEGMENT_DELIMITER_PATTERN);

        if (segments.length != CRYPTO_NUM_SEGMENTS)
            throw new InvalidEncodingException(String.format("Crypto token is not in the expected format. Expected %d segments but found %d",
                    CRYPTO_NUM_SEGMENTS, segments.length));
        if (!SYMMETRIC_CRYPTO_TOKEN_HEADER.equals(segments[CRYPTO_SEGMENT_HEADER]))
            throw new InvalidEncodingException(String.format("Crypto token is not in the expected format. Expected '%s' header but found '%s'",
                    SYMMETRIC_CRYPTO_TOKEN_HEADER, segments[CRYPTO_SEGMENT_HEADER]));

        return segments;
    }
}
