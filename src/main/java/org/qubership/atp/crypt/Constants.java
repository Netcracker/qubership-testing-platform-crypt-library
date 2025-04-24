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

public class Constants {

    public static final String TEMPLATE_REGEXP = "\\{ENC\\}(\\{(?<iv>[a-zA-Z0-9\\=\\/\\+]*)\\}){1}(\\{"
            + "(?<cryptData>[a-zA-Z0-9\\=\\/\\+]+)\\}){1}";
    public static final Pattern TEMPLATE_PATTERN = Pattern.compile(TEMPLATE_REGEXP);
    public static final String ENCRYPT_MARKER = "{ENC}";
    public static final String RSA = "RSA";
    public static final int RSA_KEY_SIZE = 2048;
    public static final String RSA_TRANSFORMATION = "RSA";
    public static final String AES = "AES";
    public static final int AES_KEY_SIZE = 256;
    public static final String AES_MODE = "CBC";
    public static final String AES_PADDINGS = "PKCS5Padding";
    public static final String AES_TRANSFORMATION = AES + "/" + AES_MODE + "/" + AES_PADDINGS;
    public static final String PEM_BEGIN = "-----BEGIN";
    public static final String ENCRYPTED_MASK = "********";

    private Constants() {
    }
}
