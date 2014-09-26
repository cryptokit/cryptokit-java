package org.cryptokit.exception;

public class DecryptionFailedException extends RuntimeException {
    public DecryptionFailedException() {
    }

    public DecryptionFailedException(String message) {
        super(message);
    }

    public DecryptionFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public DecryptionFailedException(Throwable cause) {
        super(cause);
    }
}
