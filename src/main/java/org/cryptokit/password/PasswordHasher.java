package org.cryptokit.password;

import org.cryptokit.core.Crypto;
import org.cryptokit.core.CryptoConstants;
import org.cryptokit.core.StringUtils;
import org.cryptokit.exception.InvalidEncodingException;
import org.cryptokit.exception.InvalidInputException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.cryptokit.password.PasswordTokenSpec.*;

public class PasswordHasher {
    private int mIterations = PasswordTokenSpec.PASSWORD_HASH_DEFAULT_ITERATIONS;

    /**
     * Set the number of iterations to use when hashing the password.
     * <p/>
     * A larger number will slow down a brute force attack on a compromised
     * password hash, but will also take a longer time to compute both during
     * the initial password hashing as well as all subsequent password
     * validation attempts. Leave it at the default value unless you have a
     * good reason not to.
     *
     * @param iterations Number of iterations to use
     */
    public void setIterations(final int iterations) {
        if (iterations < 1)
            throw new InvalidInputException("Iterations must be 1 or greater");

        mIterations = iterations;
    }

    /**
     * Get the current number of iterations used when hashing passwords.
     *
     * @return Number of iterations
     */
    public int getIterations() {
        return mIterations;
    }

    /**
     * Securely hash a password into a token format suitable for storage.
     * <p/>
     * The password is transformed using a one-way cryptographic hash function
     * and packaged into a secure password token format suitable for storage
     * for example in your database. The token is fully self-contained,
     * self-identifying and future proof, you do not need to store anything
     * else related to the password such as the iteration count, algorithm
     * or format used.
     *
     * @param password The plain text password to hash
     * @return A token containing the hashed password, suitable for storage
     */
    public String hash(final String password) {
        if (StringUtils.isNullOrEmpty(password))
            throw new InvalidInputException("Password cannot be null or empty");

        final byte[] saltBytes = Crypto.generateRandomBytes(PASSWORD_SALT_BYTE_SIZE);
        final byte[] passwordHashBytes = hashPasswordUsingSalt(saltBytes, password, mIterations);
        final String passwordHashToken = encodePasswordHashToken(saltBytes, passwordHashBytes, mIterations);

        return passwordHashToken;
    }

    /**
     * Validate a password against the stored password hash token.
     * <p/>
     * The given plain text password is securely validated against the provided
     * password hash token that you stored when the password was first hashed.
     *
     * @param password          The plain text password to validate
     * @param passwordHashToken The previously stored password hash token
     * @return True if the password is valid for the given hash token
     */
    public boolean isValidPassword(final String password, final String passwordHashToken) {
        if (StringUtils.isNullOrEmpty(password))
            throw new InvalidInputException("Password cannot be null or empty");
        if (StringUtils.isNullOrEmpty(passwordHashToken))
            throw new InvalidInputException("Password hash token cannot be null or empty");

        final String[] segments = decodePasswordHashToken(passwordHashToken);
        final int iterationsUsed = Integer.parseInt(segments[PASSWORD_SEGMENT_ITERATIONS]);
        final String base64Salt = segments[PASSWORD_SEGMENT_SALT];
        final String base64HashedPassword = segments[PASSWORD_SEGMENT_HASH];
        final byte[] saltBytes = StringUtils.base64DecodeBytes(base64Salt);
        final byte[] hashedPasswordBytes = StringUtils.base64DecodeBytes(base64HashedPassword);

        final byte[] passwordHashBytes = hashPasswordUsingSalt(saltBytes, password, iterationsUsed);
        final boolean passwordMatchesHash = slowHashEquals(passwordHashBytes, hashedPasswordBytes);

        return passwordMatchesHash;
    }

    // Securely hash the password using the given salt and iteration count, using a the slow-hash PBKDF2 algorithm
    private byte[] hashPasswordUsingSalt(final byte[] saltBytes, final String password, final int iterations) {
        final byte[] passwordHashBytes;
        try {
            passwordHashBytes = Crypto.pbkdf2(password, saltBytes, iterations, PASSWORD_HASH_BYTE_SIZE);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidEncodingException("You must use a Java crypto provider that implements " + CryptoConstants.PBKDF2_HASH_ALGORITHM, e);
        } catch (InvalidKeySpecException e) {
            throw new InvalidEncodingException("Internal library error", e);
        }

        return passwordHashBytes;
    }

    // Encode the hashed password with all the metadata necessary for validation into a convenient token format
    private static String encodePasswordHashToken(final byte[] saltBytes, final byte[] passwordHashBytes, final int iterations) {
        final String base64Salt = StringUtils.base64Encode(saltBytes);
        final String base64HashedPassword = StringUtils.base64Encode(passwordHashBytes);
        final String passwordHashToken =
                PASSWORD_TOKEN_HEADER + CryptoConstants.SEGMENT_DELIMITER +
                        iterations + CryptoConstants.SEGMENT_DELIMITER +
                        base64Salt + CryptoConstants.SEGMENT_DELIMITER +
                        base64HashedPassword;

        return passwordHashToken;
    }

    // Decode the token password hash token into its constituent parts
    private static String[] decodePasswordHashToken(final String passwordHashToken) {
        final String[] segments = passwordHashToken.split(CryptoConstants.SEGMENT_DELIMITER_PATTERN);

        if (segments.length != PASSWORD_NUM_SEGMENTS)
            throw new InvalidEncodingException(String.format("Password hash is not in the expected format. Expected %d segments but found %d",
                    PASSWORD_NUM_SEGMENTS, segments.length));
        if (!PASSWORD_TOKEN_HEADER.equals(segments[PASSWORD_SEGMENT_HEADER]))
            throw new InvalidEncodingException(String.format("Password hash is not in the expected format. Expected '%s' header but found '%s'",
                    PASSWORD_TOKEN_HEADER, segments[PASSWORD_SEGMENT_HEADER]));

        return segments;
    }

    // Compare two hashes in length-constant time
    // Ensures that attackers cannot derive timing related information from
    // the process, i.e. verifying a hash that differs from the expected in
    // its first byte must take just as long as verifying a hash that
    // only differs in its last byte.
    private static boolean slowHashEquals(final byte[] a, final byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
