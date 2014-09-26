package org.cryptokit.jwk;

import com.google.gson.annotations.SerializedName;

/**
 * Value types for JSON Web Algorithms (JWA), suitable
 * for use in a JSON serialization context via Gson.
 * <p/>
 * Based on JSON Web Algorithms Draft 32, September 23, 2014
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-32
 */
public class Values {

    public enum Type {
        @SerializedName("EC")
        EC("EC"), // Elliptic Curve (Recommended+)
        @SerializedName("RSA")
        RSA("RSA"), // RSA (Required)
        @SerializedName("oct")
        OCT("oct"); // Octet sequence, for symmetric keys (Required)

        private final String text;

        private Type(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    public enum Use {
        @SerializedName("sig")
        SIGNATURE("sig"),
        @SerializedName("enc")
        ENCRYPTION("enc");

        private final String text;

        private Use(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    public enum Operations {
        @SerializedName("sign")
        SIGN("sign"), // Compute signature or MAC
        @SerializedName("verify")
        VERIFY("verify"), // Verify signature or MAC
        @SerializedName("encrypt")
        ENCRYPT("encrypt"), // Encrypt content
        @SerializedName("decrypt")
        DECRYPT("decrypt"), // Decrypt content and validate decryption, if applicable
        @SerializedName("wrapKey")
        WRAP_KEY("wrapKey"), // Encrypt key
        @SerializedName("unwrapKey")
        UNWRAP_KEY("unwrapKey"), // Decrypt key and validate decryption, if applicable
        @SerializedName("deriveKey")
        DERIVE_KEY("deriveKey"), // Derive key
        @SerializedName("deriveBits")
        DERIVE_BITS("deriveBits"); // Derive bits not to be used as a key

        private final String text;

        private Operations(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    public enum Algorithm {
        // Algorithm header parameter values for JWS
        HS256("HS256"), // HMAC using SHA-256 (Required)
        HS384("HS384"), // HMAC using SHA-384
        HS512("HS512"), // HMAC using SHA-512
        RS256("RS256"), // RSASSA-PKCS-v1_5 using SHA-256 (Recommended)
        RS384("RS384"), // RSASSA-PKCS-v1_5 using SHA-384
        RS512("RS512"), // RSASSA-PKCS-v1_5 using SHA-512
        ES256("ES256"), // ECDSA using P-256 and SHA-256 (Recommended+)
        ES384("ES384"), // ECDSA using P-384 and SHA-384
        ES512("ES512"), // ECDSA using P-521 and SHA-512
        PS256("PS256"), // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
        PS384("PS384"), // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
        PS512("PS512"), // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
        @SerializedName("none")
        NONE("none"), // No digital signature or MAC performed

        // Algorithm header parameter values for JWE
        RSA15("RSA1_5"), // RSAES-PKCS1-V1_5 (Required)
        RSAOAEP("RSA-OAEP"), // RSAES OAEP using default parameters
        RSAOAEP256("RSA-OAEP-256"), // RSAES OAEP using SHA-256 and MGF1 with SHA-256
        A128KW("A128KW"), // AES Key Wrap with default initial value using 128 bit key (Recommended)
        A192KW("A192KW"), // AES Key Wrap with default initial value using 192 bit key
        A256KW("A256KW"), // AES Key Wrap with default initial value using 256 bit key (Recommended)
        DIRECT("dir"), // Direct use of a shared symmetric key as the CEK (Recommended)
        ECDHES("ECDH-ES"), // Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF (Recommended+)
        ECDHESA128KW("ECDH-ES+A128KW"), // ECDH-ES using Concat KDF and CEK wrapped with "A128KW" (Recommended)
        ECDHESA192KW("ECDH-ES+A192KW"), // ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
        ECDHESA256KW("ECDH-ES+A256KW"), // ECDH-ES using Concat KDF and CEK wrapped with "A256KW" (Recommended)
        A128GCMKW("A128GCMKW"), // Key wrapping with AES GCM using 128 bit key
        A192GCMKW("A192GCMKW"),  // Key wrapping with AES GCM using 192 bit key
        A256GCMKW("A256GCMKW"),  // Key wrapping with AES GCM using 256 bit key
        PBES2HS256A128KW("PBES2-HS256+A128KW"), // PBES2 with HMAC SHA-256 and "A128KW" wrapping
        PBES2HS384A192KW("PBES2-HS384+A192KW"), // PBES2 with HMAC SHA-384 and "A192KW" wrapping
        PBES2HS512A256KW("PBES2-HS512+A256KW"); // PBES2 with HMAC SHA-512 and "A256KW" wrapping

        private final String text;

        private Algorithm(final String text) {
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }
}
