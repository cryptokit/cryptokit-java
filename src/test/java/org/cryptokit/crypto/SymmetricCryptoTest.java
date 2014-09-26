package org.cryptokit.crypto;

import org.apache.commons.codec.binary.Base64;
import org.cryptokit.core.CryptoConstants;
import org.cryptokit.exception.DecryptionFailedException;
import org.cryptokit.exception.InvalidEncodingException;
import org.cryptokit.exception.InvalidInputException;
import org.cryptokit.key.KeyLoader;
import org.cryptokit.key.RandomKeyGenerator;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

public class SymmetricCryptoTest {
    SymmetricCrypto crypto;
    SecretKey secretKey;

    @Before
    public void setUp() {
        secretKey = RandomKeyGenerator.generateSymmetricKey();
        crypto = new SymmetricCrypto(secretKey);
    }

    @Test(expected = InvalidInputException.class)
    public void testConstructorNullKey() {
        new SymmetricCrypto(null);
    }

    @Test
    public void testEncrypt() {
        String cryptoToken = crypto.encrypt("secret");
        validateSymmetricCryptoFormat(cryptoToken);
    }

    @Test
    public void testEncryptSameSecretTwice() {
        String cryptoToken1 = crypto.encrypt("secret");
        String cryptoToken2 = crypto.encrypt("secret");

        assertNotEquals(cryptoToken1, cryptoToken2);
    }

    @Test(expected = InvalidInputException.class)
    public void testEncryptEmpty() {
        crypto.encrypt(" ");
    }

    @Test(expected = InvalidInputException.class)
    public void testEncryptNull() {
        crypto.encrypt(null);
    }

    @Test
    public void testEncryptUnicode() {
        String cryptoToken = crypto.encrypt("秘密");
        validateSymmetricCryptoFormat(cryptoToken);
    }

    @Test
    public void testDecrypt() {
        String cryptoToken = crypto.encrypt("secret");

        assertEquals(crypto.decrypt(cryptoToken), "secret");
    }

    @Test(expected = DecryptionFailedException.class)
    public void testDecryptWithWrongKey() {
        String cryptoToken = crypto.encrypt("secret");
        SecretKey wrongKey = RandomKeyGenerator.generateSymmetricKey();
        SymmetricCrypto wrongCrypto = new SymmetricCrypto(wrongKey);

        wrongCrypto.decrypt(cryptoToken);
    }

    @Test(expected = InvalidInputException.class)
    public void testDecryptWithEmptyToken() {
        crypto.decrypt(" ");
    }

    @Test(expected = InvalidInputException.class)
    public void testDecryptWithNullToken() {
        crypto.decrypt(null);
    }

    @Test(expected = InvalidEncodingException.class)
    public void testDecryptWithGarbage() {
        crypto.decrypt("xxyyzz");
    }

    @Test
    public void testDecryptUnicode() {
        String cryptoToken = crypto.encrypt("秘密");

        assertEquals(crypto.decrypt(cryptoToken), "秘密");
    }

    @Test
    public void testDecryptKnownGoodV1Token() {
        SecretKey secretKey = KeyLoader.SymmetricKeyFromString("1234567890abcdef1234567890abcdef"); // Key must be 16 or 32 bytes
        SymmetricCrypto crypto = new SymmetricCrypto(secretKey);

        // This will detect if the token format itself is changed in some incompatible way by mistake
        assertEquals(crypto.decrypt("ck_sc1.AVfbP5ngZRkRuof1_J_Jug.pMfUTG3-j-aEUHVnScIq3Q"), "secret");
    }

    @Test(expected = InvalidEncodingException.class)
    public void testDecryptUnknownTokenVersion() {
        String invalidCryptoToken = crypto.encrypt("secret").replace(CryptoTokenSpec.SYMMETRIC_CRYPTO_TOKEN_HEADER, "ck_scX");

        crypto.decrypt(invalidCryptoToken);
    }

    @Test(expected = InvalidEncodingException.class)
    public void testDecryptUnknownTokenSegment() {
        String invalidCryptoToken = crypto.encrypt("secret") + CryptoConstants.SEGMENT_DELIMITER + "extraBit";

        crypto.decrypt(invalidCryptoToken);
    }

    private void validateSymmetricCryptoFormat(String cryptoToken) {
        String[] segments = cryptoToken.split(CryptoConstants.SEGMENT_DELIMITER_PATTERN);
        assertEquals(segments.length, CryptoTokenSpec.CRYPTO_NUM_SEGMENTS);
        assertEquals(segments[CryptoTokenSpec.CRYPTO_SEGMENT_HEADER], CryptoTokenSpec.SYMMETRIC_CRYPTO_TOKEN_HEADER);
        assertTrue(Base64.isBase64(segments[CryptoTokenSpec.CRYPTO_SEGMENT_IV]));
        assertTrue(Base64.isBase64(segments[CryptoTokenSpec.CRYPTO_SEGMENT_CIPHER]));
    }
}