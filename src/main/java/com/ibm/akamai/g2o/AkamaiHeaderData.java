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

class AkamaiHeaderData {

    String raw;
    String path;

    int version;
    String edgeIp;
    String clientIp;
    long time;
    String uniqueId;
    String nonce;

    String secret;

    AkamaiHeaderData(String path, String httpDataHeader) {
        // X-Akamai-G2O-Auth-Data: version, edge-ip, client-ip, time, unique-id, nonce
        String[] dataArray = httpDataHeader.split(",");
        if ( dataArray.length != 6 ) {
            throw new IllegalArgumentException("Bad header format");
        }

        this.path = path;
        this.raw = httpDataHeader;
        try {
            this.version = Integer.parseInt(dataArray[0].trim());
            this.edgeIp = dataArray[1].trim();
            this.clientIp = dataArray[2].trim();
            this.time = Long.parseLong(dataArray[3].trim()) * 1000;
            this.uniqueId = dataArray[4].trim();
            this.nonce = dataArray[5].trim();
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad header format", e);
        }
    }

    AkamaiHeaderData setSecret(String secret) {
        this.secret = secret;
        return this;
    }

    public String toString() {
        return "{ version: " + version
        + ", path: \"" + path
        + "\", secret: \"" + secret
        + "\", raw: \"" + raw
        + "\"}";
    }
}
