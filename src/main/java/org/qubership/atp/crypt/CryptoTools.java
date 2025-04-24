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

import java.util.regex.Matcher;

import org.apache.commons.lang.StringUtils;

public class CryptoTools {

    /**
     * Mask text if encrypted with the mask.
     *
     * @param text - data to mask
     * @param mask - to mask encrypted data with
     * @return - encrypted text
     */
    public static String maskEncryptedData(String text, String mask) {
        if (StringUtils.isEmpty(text) || !text.contains(Constants.ENCRYPT_MARKER)) {
            return text;
        }
        return text.replaceAll(getTemplateRegexp(), mask);
    }

    /**
     * Mask text if encrypted with '********' mask.
     *
     * @param text - data to mask
     * @return - encrypted text
     */
    public static String maskEncryptedData(String text) {
        return maskEncryptedData(text, Constants.ENCRYPTED_MASK);
    }

    /**
     * Get encrypted data regexp.
     *
     * @return template regexp.
     */
    public static String getTemplateRegexp() {
        return Constants.TEMPLATE_REGEXP;
    }

    /**
     * Finds encrypted text from data.
     *
     * @param data - data to find encrypted text in.
     * @return encrypted text if exists
     */
    public static String[] getEncryptedData(String data) {
        Matcher matcher = Constants.TEMPLATE_PATTERN.matcher(data);
        if (!matcher.find()) {
            return null;
        } else {
            return new String[]{matcher.group("iv"), matcher.group("cryptData")};
        }
    }

    private CryptoTools() {
    }
}
