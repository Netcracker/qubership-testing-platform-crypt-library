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

package org.qubership.atp.crypt.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.qubership.atp.crypt.AtpCryptoFactory;
import org.qubership.atp.crypt.api.Decryptor;
import org.qubership.atp.crypt.api.Encryptor;
import org.qubership.atp.crypt.exception.AtpCryptoException;

@Configuration
public class AtpEncryptorConfiguration extends AtpCryptoConfiguration {

    @Value("${atp.crypto.key:}")
    private String key;

    @Value("${atp.crypto.privateKey:}")
    private String privateKey;

    /**
     * ATP Encryptor bean.
     */
    @Bean("atpEncryptor")
    public Encryptor atpEncryptor() throws AtpCryptoException {
        validateKey(key, "atp.crypto.key");
        validateKey(privateKey, "atp.crypto.privateKey");
        Decryptor rsaDecryptor = AtpCryptoFactory.createDefaultRsaDecryptor(privateKey);
        return AtpCryptoFactory.createDefaultAesEncryptor(rsaDecryptor.decrypt(key));
    }
}
