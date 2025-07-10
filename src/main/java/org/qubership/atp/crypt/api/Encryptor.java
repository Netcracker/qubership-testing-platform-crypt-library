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

import org.qubership.atp.crypt.exception.AtpEncryptException;

public interface Encryptor {

    /**
     * Encrypt String data using key provided.
     * @param data String to be encrypted
     * @param key Object key
     * @return encrypted String
     * @throws AtpEncryptException in case encryption problems.
     */
    String encrypt(String data, Object key) throws AtpEncryptException;

    /**
     * Encrypt String data.
     * @param data String to be encrypted
     * @return encrypted String
     * @throws AtpEncryptException in case encryption problems.
     */
    String encrypt(String data) throws AtpEncryptException;
}
