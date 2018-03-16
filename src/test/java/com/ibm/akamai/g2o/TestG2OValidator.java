/*
 * Copyright (c) 2018 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.akamai.g2o;

import java.util.HashMap;
import java.util.Map;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

public class TestG2OValidator {
    static String secret = "s3cr3tk3y";
    static String header = "5, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1";
    static String urlPath = "/abc";
    static String signature = "d/8DhQppXfD8WvbEP5TU3UVrPxgifX4LumVfadVPxgk=";

    SignatureValidator validator;

    @After
    public void clear() {
        validator = null;
    }

    @Test(expected=IllegalArgumentException.class)
    public void testNullNonce() {
        validator = new SignatureValidator((String) null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testEmptyNonce() {
        validator = new SignatureValidator((String) "");
    }

    @Test(expected=IllegalArgumentException.class)
    public void testNullNonceMap() {
        validator = new SignatureValidator((Map<String, String>) null);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testEmptyNonceMap() {
        validator = new SignatureValidator(new HashMap<>());
    }

    @Test
    public void testMatchingNonce() {
        // Note this is using the secret in the v1 nonce,
        // which is referenced in the header data above
        validator = new SignatureValidator("v1:"+secret+",nonce1:Others3cr3t")
                .setTimeWindow(0); // disable time validation

        VerificationResult result = validator.validate(urlPath, header, signature);
        Assert.assertNull("Request should be valid: " + result.getMessage(),
                result.getMessage());
        Assert.assertTrue(result.isValid());
    }
    @Test
    public void testMatchingNonceReal() {
        // Note this is using the secret in the v1 nonce,
        // which is referenced in the header data above
        validator = new SignatureValidator("201801:YlfntaC30yCKTsBiWZcaebiYIrMZIlkr5BHQYzN8F0no7kdb")
                .setTimeWindow(0); // disable time validation

        VerificationResult result = validator.validate("/api/login",
            "3, 66.171.227.33, 12.47.205.126, 1523292185, -1646207363.570684466, 201801",
            "izn88YCmyQ5RprVcxSYCSw==");

        Assert.assertNull("Request should be valid: " + result.getMessage(),
                result.getMessage());
        Assert.assertTrue(result.isValid());
    }


    @Test
    public void testWrongSecret() {
        validator = new SignatureValidator("nomatch:randomSecret")
                .setTimeWindow(0); // disable time validation

        VerificationResult result = validator.validate(urlPath, header, signature);
        Assert.assertNotNull("Request should not be valid: " + result.getMessage(),
                result.getMessage());
        Assert.assertFalse(result.isValid());
    }

    @Test
    public void testOldTimestamp() {
        validator = new SignatureValidator("nomatch:randomSecret");

        VerificationResult result = validator.validate(urlPath, header, signature);
        Assert.assertNotNull("Request should not be valid: " + result.getMessage(),
                result.getMessage());
        Assert.assertFalse(result.isValid());
    }
}
