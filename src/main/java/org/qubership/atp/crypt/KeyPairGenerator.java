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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.qubership.atp.crypt.api.Decryptor;
import org.qubership.atp.crypt.api.Encryptor;
import org.qubership.atp.crypt.api.KeyEntity;

public class KeyPairGenerator {

    /**
     * Array of correct lengths of AES KEY.
     * Checking is performed in the readKey method.
     */
    private static final List<Integer> AES_KEY_CORRECT_LENGTH = new ArrayList<>(Arrays.asList(16, 24, 32));

    /**
     * Generation of RSA and AES keys (stub implementation).
     *
     * @return KeyEntity - key entity generated.
     **/
    public KeyEntity generateKeys() {
        return generateKeys("");
    }

    /**
     * Generation of RSA and encryption the incoming AES key (stub implementation).
     *
     * @param key the key
     * @return the key entity
     */
    public KeyEntity generateKeys(final String key) {
        return new KeyEntity(key, "", "", "");
    }

    /**
     * To generate pair key from console.
     *
     * @param arg the input arguments
     * @throws Exception the exception
     */
    public static void main(final String[] arg) throws Exception {
        int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("Max Key Size for AES = " + maxKeySize);
        KeyPairGenerator generator = new KeyPairGenerator();
        KeyEntity keys;
        if (null != arg && arg.length > 0 && null != arg[0] && StringUtils.isNotEmpty(arg[0])) {
            keys = generator.generateKeys(arg[0]);
        } else {
            keys = generator.generateKeys();
        }
        System.out.println(keys);
        System.out.println();
        System.out.println("Encryption/Decryption test...");
        Encryptor encryptor = AtpCryptoFactory.createDefaultAesEncryptor(keys.getKey());
        String encryptedData = encryptor.encrypt("Key is valid");
        System.out.println("Encrypted data = " + encryptedData);
        Decryptor decryptor = AtpCryptoFactory.createDefaultAesDecryptor(keys.getKey());
        System.out.println("Decrypted data = " + decryptor.decrypt(encryptedData));
    }

    /**
     * Read the base32 form of a public key.
     * @param publicKey - Key String to read from
     * @return Object key.
     **/
    public Object readPublicKey(final String publicKey) {
        return new Object();
    }

    /**
     * Read the base32 form of a private key.
     * @param privateKeyString - Key String to read from
     * @return Object key.
     **/
    public Object readPrivateKey(final String privateKeyString) {
        return new Object();
    }

    /**
     * Read the base32 form of an AES key.
     * @param keyString - Key String to read from
     * @return Object key.
     **/
    public Object readKey(final String keyString) {
        return new Object();
    }
}
