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

package org.qubership.atp.crypt.impl;

import org.qubership.atp.crypt.api.CryptoProvider;
import org.qubership.atp.crypt.api.Decryptor;
import org.qubership.atp.crypt.exception.AtpDecryptException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DecryptorImpl implements Decryptor {

    private final String transformation;
    private final Object key;
    private final CryptoProvider provider;

    /**
     * Instantiates a new Decryptor.
     *
     * @param provider the provider
     */
    public DecryptorImpl(String transformation, CryptoProvider provider, Object key) {
        this.transformation = transformation;
        this.provider = provider;
        this.key = key;
    }

    public boolean isEncrypted(String data) {
        return provider.isEncrypted(data);
    }

    @Override
    public String decrypt(String encryptedData)
            throws AtpDecryptException {
        return decrypt(encryptedData, key);
    }

    @Override
    public String decrypt(String encryptedData, Object key)
            throws AtpDecryptException {
        try {
            return provider.decrypt(transformation, encryptedData, key);
        } catch (Exception e) {
            log.error("Exception on decrypting data", e);
            throw new AtpDecryptException("Decrypting failed.", e);
        }
    }

    @Override
    public String decryptIfEncrypted(String encryptedData, Object key)
            throws AtpDecryptException {
        if (isEncrypted(encryptedData)) {
            return decrypt(encryptedData, key);
        }
        return encryptedData;
    }

    @Override
    public String decryptIfEncrypted(String encryptedData)
            throws AtpDecryptException {
        return decryptIfEncrypted(encryptedData, key);
    }

    /**
     * Decrypt and replace text if there is any encrypted data.
     * Stub implementation: Decryptor knows nothing about encryption/decryption, so simply returns the source string.
     *
     * @param text - data for decrypting
     * @return - Decrypted text
     */
    @Override
    public String decryptEncryptedPlacesInString(String text) {
        return text;
    }
}
