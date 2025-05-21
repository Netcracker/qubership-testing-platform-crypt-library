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

import org.qubership.atp.crypt.api.CryptoProvider;
import org.qubership.atp.crypt.api.Decryptor;
import org.qubership.atp.crypt.api.Encryptor;
import org.qubership.atp.crypt.exception.AtpCryptInvalidKeyException;
import org.qubership.atp.crypt.impl.DecryptorImpl;
import org.qubership.atp.crypt.impl.EncryptorImpl;
import org.qubership.atp.crypt.provider.BouncyCastleProvider;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AtpCryptoFactory {

    /**
     * Default CryptoProvider.
     */
    private static final CryptoProvider DEFAULT_PROVIDER = createBouncyCastleProvider();

    /**
     * Create Encryptor by parameters.
     *
     * @param transformation name of transformation
     * @param key encryption key
     * @param provider crypto provider
     * @return Encryptor created.
     */
    public static Encryptor createEncryptor(final String transformation,
                                            final Object key,
                                            final CryptoProvider provider) {
        return new EncryptorImpl(transformation, provider, key);
    }

    /**
     * Create Encryptor by parameters, using default crypto provider.
     *
     * @param transformation name of transformation
     * @param key encryption key
     * @return Encryptor created.
     */
    public static Encryptor createEncryptor(final String transformation, final Object key) {
        return new EncryptorImpl(transformation, getDefaultProvider(), key);
    }

    /**
     * Create Decryptor by parameters.
     *
     * @param transformation name of transformation
     * @param key encryption key
     * @param provider crypto provider
     * @return Decryptor created.
     */
    public static Decryptor createDecryptor(final String transformation,
                                            final Object key,
                                            final CryptoProvider provider) {
        return new DecryptorImpl(transformation, provider, key);
    }

    /**
     * Create Decryptor by parameters, using default crypto provider.
     *
     * @param transformation name of transformation
     * @param key encryption key
     * @return Decryptor created.
     */
    public static Decryptor createDecryptor(final String transformation, final Object key) {
        return new DecryptorImpl(transformation, getDefaultProvider(), key);
    }

    /**
     * Create AES encryptor.
     *
     * @param key encryption key
     * @return Encryptor
     * @throws AtpCryptInvalidKeyException Invalid key.
     */
    public static Encryptor createDefaultAesEncryptor(final String key) throws AtpCryptInvalidKeyException {
        CryptoProvider defaultProvider = getDefaultProvider();
        try {
            return new EncryptorImpl(Constants.AES_TRANSFORMATION, getDefaultProvider(), defaultProvider.readKey(key));
        } catch (Exception e) {
            log.error("Exception on reading private key", e);
            throw new AtpCryptInvalidKeyException("Decrypting failed. Cannot read key.", e);
        }
    }

    /**
     * Create AES decryptor.
     *
     * @param key decryption key
     * @return Decryptor
     * @throws AtpCryptInvalidKeyException Invalid key.
     */
    public static Decryptor createDefaultAesDecryptor(final String key) throws AtpCryptInvalidKeyException {
        CryptoProvider defaultProvider = getDefaultProvider();
        try {
            return new DecryptorImpl(Constants.AES_TRANSFORMATION, defaultProvider, defaultProvider.readKey(key));
        } catch (Exception e) {
            log.error("Exception on reading key", e);
            throw new AtpCryptInvalidKeyException("Decrypting failed. Cannot read key.", e);
        }
    }

    /**
     * Create RSA Encryptor.
     *
     * @param publicKey encryption key
     * @return Encryptor
     * @throws AtpCryptInvalidKeyException Invalid key.
     */
    public static Encryptor createDefaultRsaEncryptor(final String publicKey) throws AtpCryptInvalidKeyException {
        CryptoProvider defaultProvider = getDefaultProvider();
        try {
            return new EncryptorImpl(Constants.RSA_TRANSFORMATION, getDefaultProvider(),
                    defaultProvider.readPublicKey(publicKey));
        } catch (Exception e) {
            log.error("Exception on reading public key", e);
            throw new AtpCryptInvalidKeyException("Decrypting failed. Cannot read public key.", e);
        }
    }

    /**
     * Create RSA decryptor.
     *
     * @param privateKey decryption key
     * @return Decryptor
     * @throws AtpCryptInvalidKeyException Invalid key.
     */
    public static Decryptor createDefaultRsaDecryptor(final String privateKey) throws AtpCryptInvalidKeyException {
        CryptoProvider defaultProvider = getDefaultProvider();
        try {
            return new DecryptorImpl(Constants.RSA_TRANSFORMATION, getDefaultProvider(),
                    defaultProvider.readPrivateKey(privateKey));
        } catch (Exception e) {
            log.error("Exception on reading private key", e);
            throw new AtpCryptInvalidKeyException("Decrypting failed. Cannot read private key.", e);
        }
    }

    /**
     * Get Default crypto provider instance.
     *
     * @return CryptoProvider instance.
     */
    public static CryptoProvider getDefaultProvider() {
        return DEFAULT_PROVIDER;
    }

    /**
     * Create and return new BouncyCastleProvider.
     *
     * @return CryptoProvider instance.
     */
    public static CryptoProvider createBouncyCastleProvider() {
        return new BouncyCastleProvider();
    }
}
