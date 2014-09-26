package org.cryptokit.jwk;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

/**
 * Symmetric JSON Web Key (JWK)
 * In addition to the key, the algorithm intended to be used with the key should be set.
 * <p/>
 * Example:
 * SymmetricKey("keyData").setAlgorithm(Algorithm.A256KW).setOperations(Operations.ENCRYPT, Operations.DECRYPT);
 */
public class SymmetricKey extends KeyBuilder<SymmetricKey> {
    // Required parameter: Key.
    // Symmetric key octet sequence, base64url encoded.
    @SerializedName("k")
    protected String key;

    /**
     * Construct a new Symmetric JWK, given the key data
     *
     * @param key Symmetric key value, base64url encoded
     */
    public SymmetricKey(String key) {
        super(Values.Type.OCT);
        this.key = key;
    }

    public static SymmetricKey fromJson(String json) {
        Gson gson = new Gson();

        return gson.fromJson(json, SymmetricKey.class);
    }

    @Override
    protected SymmetricKey getThis() {
        return this;
    }
}
