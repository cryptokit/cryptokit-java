package org.cryptokit.jwk;

import static org.cryptokit.jwk.Values.*;

/**
 * Convenience builder for JSON Web Keys (JWK) with chaining
 * <p/>
 * Note, you should be using one of the concrete key types, EllipticCurveKey, RSAKey or SymmetricKey.
 * You can however extend this class to derive your own custom key type, gaining chaining for all
 * base parameters in the JWK specification.
 * Example:
 * SymmetricKey("keyData").setUse(Use.ENCRYPTION).setOperations(Operations.ENCRYPT, Operations.DECRYPT);
 *
 * @param <T> Concrete key type (EllipticCurveKey, RSAKey or SymmetricKey)
 */
abstract public class KeyBuilder<T> extends Key {
    protected abstract T getThis();

    protected KeyBuilder(Type type) {
        super(type);
    }

    public T setUse(Use use) {
        this.use = use;
        return getThis();
    }

    public T setOperations(Operations... operations) {
        this.operations = operations;
        return getThis();
    }

    public T setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return getThis();
    }

    public T setId(String id) {
        this.id = id;
        return getThis();
    }

    public T setX509URL(String x509URL) {
        this.x509URL = x509URL;
        return getThis();
    }

    public T setX509Chain(String... x509Chain) {
        this.x509Chain = x509Chain;
        return getThis();
    }

    public T setX509SHA1Thumbprint(String x509SHA1Thumbprint) {
        this.x509SHA1Thumbprint = x509SHA1Thumbprint;
        return getThis();
    }

    public T setX509SHA256Thumbprint(String x509SHA256Thumbprint) {
        this.x509SHA256Thumbprint = x509SHA256Thumbprint;
        return getThis();
    }
}
