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

import org.apache.commons.lang3.StringUtils;

public class ConverterTools {

    /**
     * Default charset value for the package.
     */
    public static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    /**
     * Encode input data to base64 format.
     *
     * @param data input data
     * @return base64 encoded data.
     */
    public static String encode(final byte[] data) {
        if (null == data) {
            return StringUtils.EMPTY;
        }
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decode base64 encoded data.
     *
     * @param data base64 encoded data
     * @return decoded data.
     */
    public static byte[] decode(final String data) {
        if (null == data) {
            return null;
        }
        return Base64.getDecoder().decode(stringToBytes(data));
    }

    /**
     * Convert String to byte[] with default charset.
     *
     * @param data String data to convert
     * @return byte[] converted from String with default charset.
     */
    public static byte[] stringToBytes(final String data) {
        return data.getBytes(DEFAULT_CHARSET);
    }

    /**
     * Make String from byte[] with default charset.
     *
     * @param data byte[] data to convert
     * @return String converted from byte[] with default charset.
     */
    public static String bytesToString(final byte[] data) {
        return new String(data, DEFAULT_CHARSET);
    }
}
