package org.cryptokit.exception;

public class ImplementationFailedException extends RuntimeException {
    public ImplementationFailedException() {
    }

    public ImplementationFailedException(String message) {
        super(message);
    }

    public ImplementationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public ImplementationFailedException(Throwable cause) {
        super(cause);
    }
}
