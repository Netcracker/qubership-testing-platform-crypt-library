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

package org.qubership.atp.crypt.provider;

import static org.qubership.atp.crypt.CryptoTools.getEncryptedData;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.qubership.atp.crypt.Constants;
import org.qubership.atp.crypt.ConverterTools;
import org.qubership.atp.crypt.KeyPairGenerator;
import org.qubership.atp.crypt.api.CryptoProvider;
import org.qubership.atp.crypt.api.KeyEntity;

/**
 * The Bouncy Castle provider.
 */
public class BouncyCastleProvider implements CryptoProvider {

    private static final String BC_PROVIDER = org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

    static {
        Provider provider = Security.getProvider(BC_PROVIDER);
        if (provider == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    private final KeyPairGenerator keyGenerator = new KeyPairGenerator();

    @Override
    public KeyEntity generateKeys() throws Exception {
        return keyGenerator.generateKeys();
    }

    @Override
    public Object readPublicKey(String publicKey) throws Exception {
        return keyGenerator.readPublicKey(publicKey);
    }

    @Override
    public Object readPrivateKey(String privateKey) throws Exception {
        return keyGenerator.readPrivateKey(privateKey);
    }

    @Override
    public Object readKey(String key) throws Exception {
        return keyGenerator.readKey(key);
    }

    @Override
    public String encrypt(String transformation, String data, Object key) throws Exception {
        byte[] datas = ConverterTools.stringToBytes(data);
        byte[][] encrypted = encrypt(transformation, datas, key);
        return addEncryptMarker(ConverterTools.encode(encrypted[0]), ConverterTools.encode(encrypted[1]));
    }

    private byte[][] encrypt(String transformation, byte[] data, Object key) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, BC_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, (Key) key);
        return new byte[][] {cipher.getIV(), cipher.doFinal(data)};
    }

    /**
     * Check that string is encrypted.
     * @param data data
     * @return true or false
     */
    public boolean isEncrypted(String data) {
        if (data != null) {
            String[] encryptedData = getEncryptedData(data);
            return encryptedData != null
                    && encryptedData[1] != null
                    && encryptedData[1].length() > 0;
        }
        return false;
    }

    @Override
    public String decrypt(String transformation, String data, Object key) throws Exception {
        if (!isEncrypted(data)) {
            throw new IllegalArgumentException("Wrong crypto provider for input encrypted data.");
        }
        String[] encryptedData = getEncryptedData(data);
        byte[] vector = ConverterTools.decode(encryptedData[0]);
        byte[] datas = ConverterTools.decode(encryptedData[1]);
        byte[] decrypted = decrypt(transformation, vector, datas, key);
        return ConverterTools.bytesToString(decrypted);
    }

    private byte[] decrypt(String transformation, byte[] vector, byte[] data, Object key) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation, BC_PROVIDER);
        if (null != vector && vector.length > 0) {
            cipher.init(Cipher.DECRYPT_MODE, (Key) key, new IvParameterSpec(vector));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, (Key) key);
        }
        return cipher.doFinal(data);
    }

    private String addEncryptMarker(String vector, String data) {
        return Constants.ENCRYPT_MARKER + "{" + vector + "}{" + data + "}";
    }

}
