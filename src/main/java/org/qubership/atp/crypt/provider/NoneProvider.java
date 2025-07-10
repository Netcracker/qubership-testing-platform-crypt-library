package org.qubership.atp.crypt.provider;

import java.security.Provider;

import org.qubership.atp.crypt.KeyPairGenerator;
import org.qubership.atp.crypt.api.CryptoProvider;
import org.qubership.atp.crypt.api.KeyEntity;

public class NoneProvider extends Provider implements CryptoProvider {

    public NoneProvider() {
        super("None", "1.0", "none");
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

    /**
     * Encrypt String data using transformation and key parameters given.
     * Stub implementation: Provider knows nothing about encryption/decryption, so simply returns the source string.
     *
     * @param transformation Name of transformation
     * @param data           String to be encrypted
     * @param key            Key object
     * @return Encrypted String value.
     */
    @Override
    public String encrypt(String transformation, String data, Object key) {
        return data;
    }

    /**
     * Check that string is encrypted.
     * Stub implementation: Provider knows nothing about encryption/decryption, so simply returns false.
     *
     * @param data data
     * @return true or false.
     */
    public boolean isEncrypted(String data) {
        return false;
    }

    /**
     * Decrypt String data using transformation and key parameters given.
     * Stub implementation: Provider knows nothing about encryption/decryption, so simply returns the source string.
     *
     * @param transformation Name of transformation
     * @param data           String to be decrypted
     * @param key            Key object
     * @return Decrypted String value.
     */
    @Override
    public String decrypt(String transformation, String data, Object key) {
        return data;
    }

}
