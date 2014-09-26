package org.cryptokit.exception;

public class InvalidEncodingException extends RuntimeException {
    public InvalidEncodingException() {
    }

    public InvalidEncodingException(String message) {
        super(message);
    }

    public InvalidEncodingException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidEncodingException(Throwable cause) {
        super(cause);
    }
}
