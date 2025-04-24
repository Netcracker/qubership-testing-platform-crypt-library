/*
 * # Copyright 2024-2025 NetCracker Technology Corporation
 * #
 * # Licensed under the Apache License, Version 2.0 (the "License");
 * # you may not use this file except in compliance with the License.
 * # You may obtain a copy of the License at
 * #
 * #      http://www.apache.org/licenses/LICENSE-2.0
 * #
 * # Unless required by applicable law or agreed to in writing, software
 * # distributed under the License is distributed on an "AS IS" BASIS,
 * # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * # See the License for the specific language governing permissions and
 * # limitations under the License.
 */

package org.qubership.atp.crypt;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.apache.commons.lang.StringUtils;

public class ConverterTools {

    public static final Charset defaultCharset = StandardCharsets.UTF_8;

    /**
     * Encode input data to base64 format.
     * @param data input data
     * @return base64 encoded data
     */
    public static String encode(byte[] data) {
        if (null == data) {
            return StringUtils.EMPTY;
        }
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decode base64 encoded data.
     * @param data base64 encoded data
     * @return decoded data
     */
    public static byte[] decode(String data) {
        if (null == data) {
            return null;
        }
        return Base64.getDecoder().decode(stringToBytes(data));
    }

    public static byte[] stringToBytes(String data) {
        return data.getBytes(defaultCharset);
    }

    public static String bytesToString(byte[] data) {
        return new String(data, defaultCharset);
    }
}
