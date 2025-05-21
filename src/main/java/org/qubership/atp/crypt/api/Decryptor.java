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

package org.qubership.atp.crypt.api;

import org.qubership.atp.crypt.exception.AtpDecryptException;

public interface Decryptor {

    /**
     * Decrypt encryptedData String.
     * @param encryptedData String to be decrypted
     * @return decrypted String
     * @throws AtpDecryptException in case decryption problems.
     */
    String decrypt(String encryptedData) throws AtpDecryptException;

    /**
     * Decrypt encryptedData String.
     * @param encryptedData String to be decrypted
     * @param key Key object
     * @return decrypted String
     * @throws AtpDecryptException in case decryption problems.
     */
    String decrypt(String encryptedData, Object key) throws AtpDecryptException;

    /**
     * Decrypt encryptedData String if it's encrypted.
     * @param encryptedData String possibly encrypted
     * @return decrypted String if encryptedData was really encrypted, otherwise returns original string
     * @throws AtpDecryptException in case decryption problems.
     */
    String decryptIfEncrypted(String encryptedData) throws AtpDecryptException;

    /**
     * Decrypt encryptedData String if it's encrypted.
     * @param encryptedData String possibly encrypted
     * @param key  Key object
     * @return decrypted String if encryptedData was really encrypted, otherwise returns original string
     * @throws AtpDecryptException in case decryption problems.
     */
    String decryptIfEncrypted(String encryptedData, Object key) throws AtpDecryptException;

    /**
     * Check if String data parameter is encrypted or not.
     * @param data String to check
     * @return true if String is encrypted, otherwise false.
     */
    boolean isEncrypted(String data);

    /**
     * Decrypt encrypted parts of String text (if any).
     * @param text String possibly containing encrypted parts
     * @return String decrypted
     * @throws AtpDecryptException in case decryption problems.
     */
    String decryptEncryptedPlacesInString(String text) throws AtpDecryptException;
}
