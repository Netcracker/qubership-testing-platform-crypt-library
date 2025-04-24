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
import org.qubership.atp.crypt.api.Encryptor;
import org.qubership.atp.crypt.exception.AtpEncryptException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EncryptorImpl implements Encryptor {

    private final String transformation;
    private final Object key;
    private final CryptoProvider provider;


    /**
     * Instantiates a new Encryptor.
     *
     * @param provider        the provider
     * @param key the key string
     */
    public EncryptorImpl(String transformation, CryptoProvider provider, Object key) {
        this.transformation = transformation;
        this.key = key;
        this.provider = provider;
    }

    @Override
    public String encrypt(String data, Object key) throws AtpEncryptException {
        try {
            return provider.encrypt(transformation, data, key);
        } catch (Exception e) {
            throw new AtpEncryptException("Encrypting failed.", e);
        }
    }

    @Override
    public String encrypt(String data) throws AtpEncryptException {
        return encrypt(data, key);
    }
}
