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

public interface CryptoProvider {

    /**
     * Generate Keys.
     * @return KeyEntity containing generated keys
     * @throws Exception in case some encryption problems.
     */
    KeyEntity generateKeys() throws Exception;

    /**
     * Read public key from string parameter.
     * @param publicKey String to read key
     * @return Object - public key read
     * @throws Exception in case some encryption problems.
     */
    Object readPublicKey(String publicKey) throws Exception;

    /**
     * Read private key from string parameter.
     * @param privateKey String to read key
     * @return Object - private key read
     * @throws Exception in case some encryption problems.
     */
    Object readPrivateKey(String privateKey) throws Exception;

    /**
     * Read key from string parameter.
     * @param key String to read key
     * @return Object - key read
     * @throws Exception in case some encryption problems.
     */
    Object readKey(String key) throws Exception;

    /**
     * Encrypt String data using transformation and key provided.
     * @param transformation Name of transformation, as used in javax.crypto.Cipher
     * @param data String to be encrypted
     * @param key Key object
     * @return String - encrypted String
     * @throws Exception in case some encryption problems.
     */
    String encrypt(String transformation, String data, Object key) throws Exception;

    /**
     * Decrypt String data using transformation and key provided.
     * @param transformation Name of transformation, as used in javax.crypto.Cipher
     * @param data String to be decrypted
     * @param key Key object
     * @return String - decrypted String
     * @throws Exception in case some encryption problems.
     */
    String decrypt(String transformation, String data, Object key) throws Exception;

    /**
     * Check if String data parameter is encrypted or not.
     * @param data String to check
     * @return true if String is encrypted, otherwise false.
     */
    boolean isEncrypted(String data);
}
