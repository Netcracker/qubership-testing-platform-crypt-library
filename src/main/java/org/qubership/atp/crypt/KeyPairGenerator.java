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

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
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
     * Generation of RSA and AES keys.
     * @return KeyEntity - key entity generated.
     **/
    public KeyEntity generateKeys() throws Exception {
        // Generate AES key
        SecretKey secretKey = generateAesKey();

        // Encrypt AES key with RSA public key
        String key = ConverterTools.encode(secretKey.getEncoded());
        return generateKeys(key);
    }

    /**
     * Generation of RSA and encryption the incoming AES key.
     *
     * @param key the key
     * @return the key entity
     * @throws Exception the exception
     */
    public KeyEntity generateKeys(final String key) throws Exception {
        // Generate RSA keys
        KeyPair kp = generateRsaKeyPair();

        String privateKey = ConverterTools.encode(kp.getPrivate().getEncoded());
        String publicKey = ConverterTools.encode(kp.getPublic().getEncoded());

        // Encrypt AES key with RSA public key
        Encryptor encryptor = AtpCryptoFactory.createDefaultRsaEncryptor(publicKey);
        String encryptedKey = encryptor.encrypt(key);

        return new KeyEntity(key, encryptedKey, publicKey, privateKey);
    }

    private SecretKey generateAesKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(Constants.AES);
        keyGenerator.init(Constants.AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        java.security.KeyPairGenerator rsa = java.security.KeyPairGenerator.getInstance(Constants.RSA);
        rsa.initialize(Constants.RSA_KEY_SIZE);
        return rsa.generateKeyPair();
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
    public Object readPublicKey(final String publicKey) throws Exception {
        KeyFactory factory = KeyFactory.getInstance(Constants.RSA);
        if (publicKey.trim().startsWith(Constants.PEM_BEGIN)) {
            try (StringReader keyReader = new StringReader(publicKey);
                 PemReader pemReader = new PemReader(keyReader)) {

                PemObject pemObject = pemReader.readPemObject();
                byte[] content = pemObject.getContent();
                X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
                return factory.generatePublic(pubKeySpec);
            }
        } else {
            byte[] keyBytes = ConverterTools.decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return factory.generatePublic(spec);
        }
    }

    /**
     * Read the base32 form of a private key.
     * @param privateKeyString - Key String to read from
     * @return Object key.
     **/
    public Object readPrivateKey(final String privateKeyString) throws Exception {
        KeyFactory factory = KeyFactory.getInstance(Constants.RSA);
        if (privateKeyString.trim().startsWith(Constants.PEM_BEGIN)) {
            try (StringReader keyReader = new StringReader(privateKeyString);
                 PemReader pemReader = new PemReader(keyReader)) {

                PemObject pemObject = pemReader.readPemObject();
                byte[] content = pemObject.getContent();
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
                return factory.generatePrivate(privateKeySpec);
            }
        } else {
            byte[] keyBytes = ConverterTools.decode(privateKeyString);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return factory.generatePrivate(spec);
        }
    }

    /**
     * Read the base32 form of an AES key.
     * @param keyString - Key String to read from
     * @return Object key.
     **/
    public Object readKey(final String keyString) throws Exception {
        byte[] bytes;
        if (keyString.trim().startsWith(Constants.PEM_BEGIN)) {
            try (StringReader keyReader = new StringReader(keyString);
                 PemReader pemReader = new PemReader(keyReader)) {

                PemObject pemObject = pemReader.readPemObject();
                bytes = pemObject.getContent();
            }
        } else {
            bytes = ConverterTools.decode(keyString);
        }

        if (!AES_KEY_CORRECT_LENGTH.contains(bytes.length)) {
            throw new IllegalArgumentException("Wrong length for AES key");
        }
        return new SecretKeySpec(bytes, Constants.AES);
    }
}
