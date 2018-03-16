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

public class SignatureValidator {

    public static final String AUTH_SIGNATURE_DATA_HEADER = "X-Akamai-G2O-Auth-Data";
    public static final String AUTH_SIGNATURE_SIGN_HEADER = "X-Akamai-G2O-Auth-Sign";

    /**
     * Number of seconds before or after which the difference between the server
     * and request times will trigger an authentication error. Set to 0 to disable
     * check entirely.
     */
    private long timeWindow;

    /**
     * Akamai nonce/secret pairs.
     * This allows multiple secrets to be used when transitioning between old and new values.
     *
     * Can be set using a single string format:  "key1:secret1,key2:secret2"
     */
    private Map<String, String> secrets = new HashMap<>();

    public SignatureValidator(Map<String, String> secrets) {
        this.timeWindow = 30 *  1000; // 30s

        if ( secrets == null || secrets.isEmpty() ){
            throw new IllegalArgumentException("Must specify at least one nonce");
        }
        this.secrets.putAll(secrets);
    }

    public SignatureValidator(String authNonceSecrets) {
        this(parseNonceString(authNonceSecrets));
    }

    public SignatureValidator setTimeWindow(long timeWindow) {
        this.timeWindow = ( timeWindow < 0 ) ? 0 : timeWindow;
        return this;
    }

    public VerificationResult validate(String urlString,
            String httpDataHeader,
            String httpSignature) {

        if ( httpSignature == null || httpSignature.isEmpty() ) {
            return VerificationResult.failed(httpSignature, "No signature header present");
        }

        if ( httpDataHeader == null || httpDataHeader.isEmpty() ) {
            return VerificationResult.failed(httpSignature, "No data header present");
        }

        AkamaiHeaderData data;

        try {
            data =  new AkamaiHeaderData(urlString, httpDataHeader);
            data.setSecret(secrets.containsKey(data.nonce) ? secrets.get(data.nonce) : null);
            if ( data.secret == null || data.secret.isEmpty() ) {
                return  VerificationResult.failed(httpSignature, "Invalid secret");
            }

            checkDuplicate(data);
            checkExpiry(data);

            // Create a signature and make sure it matches
            String testSignature = Signer.sign(data);
            if ( !httpSignature.equals(testSignature) ) {
                return  VerificationResult.failed(httpSignature, "Invalid signature");
            }
        } catch (Exception e) {
            return  VerificationResult.failed(httpSignature, e.getMessage());
        }

        return VerificationResult.verified(httpSignature);
    }

    /**
     * Check signature against recently seen signatures to guard against
     * replay attacks.
     *
     * @param timedCache Timed cache instance containing recently seen signatures
     * @return this
     */
    public void checkDuplicate(AkamaiHeaderData data) {
        // TODO
    }

    /**
     * Make sure we only look at young requests
     * @return this
     */
    public void checkExpiry(AkamaiHeaderData data) {
        if ( timeWindow > 0 ) {
            long now = System.currentTimeMillis();
            if (Math.abs(now - data.time) > 1000 * timeWindow) {
                throw new IllegalStateException("Signature expired");
            }
        }
    }

    /**
     * Take a single string parameter containing multiple secrets,
     * and split them apart into a map
     *
     * @param authNonceSecrets A string of the format: "key1:secret1,key2:secret2"
     * @return parsed map of keys and secrets
     */
    private static Map<String, String> parseNonceString(String authNonceSecrets) {
        Map<String, String> nonce = new HashMap<String, String>();
        if ( authNonceSecrets != null && !authNonceSecrets.isEmpty() ) {
            String[] nonceSecrets =  authNonceSecrets.split(",");
            for (String nonceSecret : nonceSecrets) {
                String[] parts = nonceSecret.trim().split(":");
                if ( parts.length == 2 )
                    nonce.put(parts[0].trim(), parts[1].trim());
            }
        }
        return nonce;
    }
}
