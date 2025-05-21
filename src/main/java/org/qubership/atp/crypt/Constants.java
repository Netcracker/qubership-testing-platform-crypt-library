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

import java.util.regex.Pattern;

public final class Constants {

    /**
     * Regular expression to determine encrypted strings.
     */
    public static final String TEMPLATE_REGEXP = "\\{ENC\\}(\\{(?<iv>[a-zA-Z0-9\\=\\/\\+]*)\\}){1}(\\{"
            + "(?<cryptData>[a-zA-Z0-9\\=\\/\\+]+)\\}){1}";

    /**
     * Compiled pattern to determine encrypted strings.
     */
    public static final Pattern TEMPLATE_PATTERN = Pattern.compile(TEMPLATE_REGEXP);

    /**
     * Encrypted string marker.
     */
    public static final String ENCRYPT_MARKER = "{ENC}";

    /**
     * RSA name.
     */
    public static final String RSA = "RSA";

    /**
     * RSA Key size.
     */
    public static final int RSA_KEY_SIZE = 2048;

    /**
     * RSA Transformation type.
     */
    public static final String RSA_TRANSFORMATION = "RSA";

    /**
     * AES encryption type.
     */
    public static final String AES = "AES";

    /**
     * Size of AES key.
     */
    public static final int AES_KEY_SIZE = 256;

    /**
     * Canonical name of AES Mode.
     */
    public static final String AES_MODE = "CBC";

    /**
     * Canonical name of AES Paddings.
     */
    public static final String AES_PADDINGS = "PKCS5Padding";

    /**
     * Canonical name of AES Transformation.
     */
    public static final String AES_TRANSFORMATION = AES + "/" + AES_MODE + "/" + AES_PADDINGS;

    /**
     * PEM Key prefix.
     */
    public static final String PEM_BEGIN = "-----BEGIN";

    /**
     * Mask used to log/output encrypted values.
     */
    public static final String ENCRYPTED_MASK = "********";

    private Constants() {
    }
}
