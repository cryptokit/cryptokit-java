package org.cryptokit.exception;

public class EncodingException extends RuntimeException {
    public EncodingException() {
    }

    public EncodingException(String message) {
        super(message);
    }

    public EncodingException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncodingException(Throwable cause) {
        super(cause);
    }
}
