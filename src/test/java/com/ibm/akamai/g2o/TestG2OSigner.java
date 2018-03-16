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

import java.net.URISyntaxException;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;


/**
 * Test data lifted from https://github.com/akamai/AkamaiOPEN-edgegrid-java
 *
 */
@RunWith(Parameterized.class)
public class TestG2OSigner {

    int version;
    String path;
    String secret;
    String authHeaderData;
    String authSignature;

    public TestG2OSigner(int version, String path, String authHeaderData, String secret,
            String authSignature) {
        super();
        this.version = version;
        this.path = path;
        this.secret = secret;
        this.authHeaderData = authHeaderData;
        this.authSignature = authSignature;
    }

    @Test
    public void test() throws Exception {
        System.out.println(this);
        AkamaiHeaderData headerData = new AkamaiHeaderData(path, authHeaderData).setSecret(secret);
        String testSignature = Signer.sign(headerData);
        Assert.assertEquals(authSignature, testSignature);
    }

    @Parameters
    public static Object[][] basicTests() throws URISyntaxException {

        return new Object[][]{
            {
                /*version:*/ 1,
                /*signString:*/ "/abc",
                /*authData:*/ "1, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1",
                /*key:*/ "s3cr3tk3y",
                /*signature:*/ "FWvsJT8JBKvnZ4jGiE7uYA=="
            },
            {
                /*version:*/ 2,
                /*signString:*/ "/abc",
                /*authData:*/ "2, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1",
                /*key:*/ "s3cr3tk3y",
                /*signature:*/ "LL4EzlYZG9DWKjDYegZf7Q=="
            },
            {
                /*version:*/ 3,
                /*signString:*/ "/abc",
                /*authData:*/ "3, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1",
                /*key:*/ "s3cr3tk3y",
                /*signature:*/ "D2+ASTlqs3WfCC5EBIhtjA=="
            },
            {
                /*version:*/ 4,
                /*signString:*/ "/abc",
                /*authData:*/ "4, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1",
                /*key:*/ "s3cr3tk3y",
                /*signature:*/ "OLU/4N3Sc5gvy7Ta/e1rzMgPb2g="
            },
            {
                /*version:*/ 5,
                /*signString:*/ "/abc",
                /*authData:*/ "5, 1.2.3.4, 3.4.5.6, 1471524574, 2805760.691583751, v1",
                /*key:*/ "s3cr3tk3y",
                /*signature:*/ "d/8DhQppXfD8WvbEP5TU3UVrPxgifX4LumVfadVPxgk=",
            },
            {
                /*version:*/ 3,
                /*signString:*/ "/api/login",
                /*authData:*/ "3, 66.171.227.33, 12.47.205.126, 1523292185, -1646207363.570684466, 201801",
                /*key:*/ "YlfntaC30yCKTsBiWZcaebiYIrMZIlkr5BHQYzN8F0no7kdb",
                /*signature:*/ "izn88YCmyQ5RprVcxSYCSw==",
            },
        };
    }

    public String toString() {
        return "{ version: " + version
        + ", path: \"" + path
        + "\", secret: \"" + secret
        + "\", authHeaderData: \"" + authHeaderData
        + "\", authSignature: \"" + authSignature
        + "\"}";
    }
}
