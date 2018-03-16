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

import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signer {
    public static final String UTF8 = "UTF-8";
    static final String HmacMD5 = "HmacMD5";
    static final String HmacSHA1 = "HmacSHA1";
    static final String HmacSHA256 = "HmacSHA256";
    static final String MD5 = "MD5";

    public static String sign(AkamaiHeaderData data) throws Exception {
        switch(data.version) {
          case 1: return version1(data);
          case 2: return version2(data);
          case 3: return version3(data);
          case 4: return version4(data);
          case 5: return version5(data);
          default: throw new IllegalArgumentException("Unknown version");
        }
    }

    // version 1: MD5(key,data,sign-string)
    static String version1(AkamaiHeaderData data) throws Exception {
        byte[] content = (data.secret + data.raw + data.path).getBytes(UTF8);

        MessageDigest md = MessageDigest.getInstance(MD5);
        md.update(content);
        return Base64.getEncoder().encodeToString(md.digest());
    }

    // version 2: MD5(key,MD5(key,data,sign-string))
    static String version2(AkamaiHeaderData data) throws Exception {
        MessageDigest md1 = MessageDigest.getInstance(MD5);
        md1.update(data.secret.getBytes(UTF8));
        md1.update(data.raw.getBytes(UTF8));
        md1.update(data.path.getBytes(UTF8));

        MessageDigest md2 = MessageDigest.getInstance(MD5);
        md2.update(data.secret.getBytes(UTF8));
        md2.update(md1.digest());
        return Base64.getEncoder().encodeToString(md2.digest());
    }

    // version 3: MD5-HMAC(key,data,sign-string)
    static String version3(AkamaiHeaderData data) throws Exception {
        Mac mac = Mac.getInstance(HmacMD5);
        mac.init(new SecretKeySpec(data.secret.getBytes(UTF8), HmacMD5));
        mac.update(data.raw.getBytes(UTF8));
        mac.update(data.path.getBytes(UTF8));

        return Base64.getEncoder().encodeToString( mac.doFinal() );
    }

    // version 4: SHA1-HMAC(key,data,sign-string)
    static String version4(AkamaiHeaderData data) throws Exception{
        Mac mac = Mac.getInstance(HmacSHA1);
        mac.init(new SecretKeySpec(data.secret.getBytes(UTF8), HmacSHA1));
        mac.update(data.raw.getBytes(UTF8));
        mac.update(data.path.getBytes(UTF8));

        return Base64.getEncoder().encodeToString( mac.doFinal() );
    }

    // version 5: SHA256-HMAC(key,data,sign-string)
    static String version5(AkamaiHeaderData data) throws Exception{
        Mac mac = Mac.getInstance(HmacSHA256);
        mac.init(new SecretKeySpec(data.secret.getBytes(UTF8), HmacSHA256));
        mac.update(data.raw.getBytes(UTF8));
        mac.update(data.path.getBytes(UTF8));

        return Base64.getEncoder().encodeToString( mac.doFinal() );
    }
}
