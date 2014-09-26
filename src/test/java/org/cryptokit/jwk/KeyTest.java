package org.cryptokit.jwk;

import org.junit.Assert;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;

public class KeyTest {

    @Test
    public void testToJson() throws Exception {
        SymmetricKey key = new SymmetricKey("keyData")
                .setUse(Values.Use.ENCRYPTION)
                .setOperations(Values.Operations.DECRYPT, Values.Operations.ENCRYPT)
                .setAlgorithm(Values.Algorithm.ES256)
                .setId("testId")
                .setX509URL("http://www.example.com")
                .setX509Chain("xxx", "yyy")
                .setX509SHA1Thumbprint("x1x1")
                .setX509SHA256Thumbprint("y1y1");

        String json = key.toJson();
        Assert.assertThat(json, containsString("keyData"));
        Assert.assertThat(json, containsString("\"enc\""));
        Assert.assertThat(json, containsString("\"decrypt\""));
        Assert.assertThat(json, containsString("\"encrypt\""));
        Assert.assertThat(json, containsString("\"ES256\""));
        Assert.assertThat(json, containsString("\"testId\""));
        Assert.assertThat(json, containsString("\"xxx\""));
        Assert.assertThat(json, containsString("\"yyy\""));
        Assert.assertThat(json, containsString("\"x1x1\""));
        Assert.assertThat(json, containsString("\"y1y1\""));
    }

    @Test
    public void testAsPrettyJson() throws Exception {
        SymmetricKey key = new SymmetricKey("keyData")
                .setUse(Values.Use.ENCRYPTION)
                .setOperations(Values.Operations.DECRYPT, Values.Operations.ENCRYPT)
                .setAlgorithm(Values.Algorithm.ES256)
                .setId("testId")
                .setX509URL("http://www.example.com")
                .setX509Chain("xxx", "yyy")
                .setX509SHA1Thumbprint("x1x1")
                .setX509SHA256Thumbprint("y1y1");

        String json = key.toPrettyJson();
        Assert.assertThat(json, containsString("keyData"));
        Assert.assertThat(json, containsString("\"enc\""));
        Assert.assertThat(json, containsString("\"decrypt\""));
        Assert.assertThat(json, containsString("\"encrypt\""));
        Assert.assertThat(json, containsString("\"ES256\""));
        Assert.assertThat(json, containsString("\"testId\""));
        Assert.assertThat(json, containsString("\"xxx\""));
        Assert.assertThat(json, containsString("\"yyy\""));
        Assert.assertThat(json, containsString("\"x1x1\""));
        Assert.assertThat(json, containsString("\"y1y1\""));
    }
}