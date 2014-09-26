package org.cryptokit.jwk;

import org.junit.Assert;
import org.junit.Test;

import static org.cryptokit.jwk.Values.*;
import static org.hamcrest.CoreMatchers.containsString;

public class SymmetricKeyTest {
    @Test
    public void testConstructor() {
        SymmetricKey key = new SymmetricKey("keyData");
        Assert.assertEquals(key.toJson(), "{\"k\":\"keyData\",\"kty\":\"oct\"}");
    }

    @Test
    public void testFromJson() {
        SymmetricKey key = new SymmetricKey("keyData")
                .setUse(Use.ENCRYPTION)
                .setOperations(Operations.DECRYPT, Operations.ENCRYPT)
                .setAlgorithm(Algorithm.ES256)
                .setId("testId")
                .setX509URL("http://www.example.com")
                .setX509Chain("xxx", "yyy")
                .setX509SHA1Thumbprint("x1x1")
                .setX509SHA256Thumbprint("y1y1");
        String json = key.toJson();

        SymmetricKey keyFromJson = SymmetricKey.fromJson(json);
        String json2 = keyFromJson.toJson();

        Assert.assertEquals(json, json2);
        Assert.assertThat(json2, containsString("keyData"));
        Assert.assertThat(json2, containsString("\"enc\""));
        Assert.assertThat(json2, containsString("\"decrypt\""));
        Assert.assertThat(json2, containsString("\"encrypt\""));
        Assert.assertThat(json2, containsString("\"ES256\""));
        Assert.assertThat(json2, containsString("\"testId\""));
        Assert.assertThat(json2, containsString("\"xxx\""));
        Assert.assertThat(json2, containsString("\"yyy\""));
        Assert.assertThat(json2, containsString("\"x1x1\""));
        Assert.assertThat(json2, containsString("\"y1y1\""));
    }
}
