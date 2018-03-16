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

public class VerificationResult {

    private boolean authenticated;
    private String message;

    public static VerificationResult verified(String signature) {
        VerificationResult response = new VerificationResult();
        response.authenticated = true;
        response.message = null;

        return response;
    }

    public static VerificationResult failed(String signature, String message) {
        VerificationResult response = new VerificationResult();
        response.authenticated = false;
        response.message = message;

        return response;
    }

    public boolean isValid() {
        return authenticated;
    }
    public String getMessage() {
        return message;
    }
}
