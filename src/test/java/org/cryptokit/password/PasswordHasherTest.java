package org.cryptokit.password;

import org.apache.commons.codec.binary.Base64;
import org.cryptokit.core.CryptoConstants;
import org.cryptokit.exception.EncodingException;
import org.cryptokit.exception.InputException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class PasswordHasherTest {
    PasswordHasher hasher;

    @Before
    public void setUp() {
        hasher = new PasswordHasher();
    }

    @Test
    public void testHash() {
        String hashedPassword = hasher.hash("password");

        validateHashFormat(hashedPassword);
    }

    @Test
    public void testHashSamePasswordTwice() {
        String hashedPassword1 = hasher.hash("password");
        String hashedPassword2 = hasher.hash("password");

        assertNotEquals(hashedPassword1, hashedPassword2);
    }

    @Test
    public void testIterations() {
        assertEquals(hasher.getIterations(), PasswordConstants.PASSWORD_HASH_DEFAULT_ITERATIONS);
        hasher.setIterations(10000);
        assertEquals(hasher.getIterations(), 10000);
    }

    @Test(expected = InputException.class)
    public void testZeroIterations() {
        hasher.setIterations(0);
    }

    @Test
    public void testHashWithIterations() {
        hasher.setIterations(10000);
        String hashedPassword = hasher.hash("password");

        validateHashFormat(hashedPassword);
    }

    @Test(expected = InputException.class)
    public void testHashEmpty() {
        String hashedPassword = hasher.hash(" ");

        validateHashFormat(hashedPassword);
    }

    @Test(expected = InputException.class)
    public void testHashNull() {
        hasher.hash(null);
    }

    @Test
    public void testHashUnicode() {
        String hashedPassword = hasher.hash("密码");

        validateHashFormat(hashedPassword);
    }

    @Test
    public void testIsValidPassword() {
        String hashedPassword = hasher.hash("password");

        assertTrue(hasher.isValidPassword("password", hashedPassword));
    }

    @Test
    public void testIsValidPasswordWithIterations() {
        hasher.setIterations(10000);
        String hashedPassword = hasher.hash("password");

        assertTrue(hasher.isValidPassword("password", hashedPassword));
    }

    @Test
    public void testIsValidPasswordWrongPassword() {
        String hashedPassword = hasher.hash("password");

        assertFalse(hasher.isValidPassword("wrongPassword", hashedPassword));
    }

    @Test(expected = InputException.class)
    public void testIsValidPasswordEmptyPassword() {
        String hashedPassword = hasher.hash("password");

        hasher.isValidPassword(" ", hashedPassword);
    }

    @Test(expected = InputException.class)
    public void testIsValidPasswordEmptyHash() {
        hasher.isValidPassword("password", " ");
    }


    @Test(expected = InputException.class)
    public void testIsValidPasswordNullPassword() {
        String hashedPassword = hasher.hash("password");

        hasher.isValidPassword(null, hashedPassword);
    }

    @Test(expected = InputException.class)
    public void testIsValidPasswordNullHash() {
        hasher.isValidPassword("password", null);
    }

    @Test
    public void testIsValidPasswordUnicode() {
        String hashedPassword = hasher.hash("密码");

        assertTrue(hasher.isValidPassword("密码", hashedPassword));
    }

    @Test
    public void testIsValidPasswordKnownGoodV1Hash() {
        // This will detect if the token format itself is changed in some incompatible way by mistake
        assertTrue(hasher.isValidPassword("password", "ckp1.5000.YBqOl-Kp-Laqs9NbMGLiYfnsUkrFv5J0Z8M70WumzIA.vlSKFVVPmq_QkgS-NtOOQmc5drzqTDuUCdXqo77jyYg"));
    }

    @Test(expected = EncodingException.class)
    public void testIsValidPasswordUnknownVersionHash() {
        String invalidHashedPassword = hasher.hash("password").replace(PasswordConstants.PASSWORD_TOKEN_HEADER, "ckpX");

        hasher.isValidPassword("password", invalidHashedPassword);
    }

    @Test(expected = EncodingException.class)
    public void testIsValidPasswordUnknownSegmentHash() {
        String invalidHashedPassword = hasher.hash("password") + CryptoConstants.SEGMENT_DELIMITER + "extraBit";

        hasher.isValidPassword("password", invalidHashedPassword);
    }

    private void validateHashFormat(String hashedPassword) {
        String[] segments = hashedPassword.split(CryptoConstants.SEGMENT_DELIMITER_PATTERN);
        assertEquals(segments.length, PasswordConstants.PASSWORD_NUM_SEGMENTS);
        assertEquals(segments[PasswordConstants.PASSWORD_SEGMENT_HEADER], PasswordConstants.PASSWORD_TOKEN_HEADER);
        assertTrue(Base64.isBase64(segments[PasswordConstants.PASSWORD_SEGMENT_SALT]));
        assertTrue(Base64.isBase64(segments[PasswordConstants.PASSWORD_SEGMENT_HASH]));
    }
}
