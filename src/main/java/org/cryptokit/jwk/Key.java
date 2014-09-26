package org.cryptokit.jwk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;

import static org.cryptokit.jwk.Values.*;

/**
 * A JSON Web Key (JWK) is a JavaScript Object Notation (JSON)
 * data structure that represents a cryptographic key.
 * <p/>
 * Based on JSON Web Key Draft 32, September 23, 2014
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-key-32
 */
abstract public class Key {

    // Required parameter: Key Type.
    // 'EC' (EllipticCurveKey), 'RSA' (RSAKey) or 'oct' (SymmetricKey).
    @SerializedName("kty")
    protected Type type;

    // Optional parameter: Public Key Use.
    // The intended use of the public key, 'sig', 'enc', or a custom value.
    protected Use use;

    // Optional parameter: Key Operations.
    // Identifies the operation(s) that the key is intended to be used for.
    @SerializedName("key_ops")
    protected Operations[] operations;

    // Optional parameter: Algorithm.
    // Identifies the algorithm intended for use with the key.
    @SerializedName("alg")
    protected Algorithm algorithm;

    // Optional parameter: Key ID.
    // Used to match a specific key, for example to choose among a set of keys during key rollover.
    @SerializedName("kid")
    protected String id;

    // Optional parameter: X.509 URL.
    // URI that refers to a resource for an X.509 public key certificate or certificate chain.
    @SerializedName("x5u")
    protected String x509URL;

    // Optional parameter: X.509 Certificate Chain.
    // A chain of one or more DER PKIX certificate values encoded as base64 strings (note: NOT base64url encoded).
    @SerializedName("x5c")
    protected String[] x509Chain;

    // Optional parameter: X.509 Certificate SHA-1 Thumbprint.
    // Base64url encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    @SerializedName("x5t")
    protected String x509SHA1Thumbprint;

    // Optional parameter: X.509 Certificate SHA-256 Thumbprint.
    // Base64url encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    @SerializedName("x5t#S256")
    protected String x509SHA256Thumbprint;

    public Key(Type type) {
        this.type = type;
    }

    public String toJson() {
        Gson gson = new Gson();
        return gson.toJson(this);
    }

    public String toPrettyJson() {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(this);
    }
}
