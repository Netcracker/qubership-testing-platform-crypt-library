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

    KeyEntity generateKeys() throws Exception;

    Object readPublicKey(String publicKey) throws Exception;

    Object readPrivateKey(String privateKey) throws Exception;

    Object readKey(String key) throws Exception;

    String encrypt(String transformation, String data, Object key) throws Exception;

    String decrypt(String transformation, String data, Object key) throws Exception;

    boolean isEncrypted(String data);
}
