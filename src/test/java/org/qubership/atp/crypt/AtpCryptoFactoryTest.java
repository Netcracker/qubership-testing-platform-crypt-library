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

import org.junit.Test;
import org.qubership.atp.crypt.exception.AtpCryptInvalidKeyException;

public class AtpCryptoFactoryTest {

    /**
     * Test of Default AES Encryptor creation in case key is not valid.
     *
     * @throws Exception in case crypto errors occurred.
     */
    @Test(expected = AtpCryptInvalidKeyException.class)
    public void testCreateDefaultAesEncryptorExpectExceptionWhenKeyIsNotValid() throws Exception {
        AtpCryptoFactory.createDefaultAesEncryptor("Invalid");
    }

    /**
     * Test of Default RSA Encryptor creation in case key is not valid.
     *
     * @throws Exception in case crypto errors occurred.
     */
    @Test(expected = AtpCryptInvalidKeyException.class)
    public void testCreateDefaultRsaEncryptorExpectExceptionWhenKeyIsNotValid() throws Exception {
        AtpCryptoFactory.createDefaultRsaEncryptor("Invalid");
    }

    /**
     * Test of Default AES Decryptor creation in case key is not valid.
     *
     * @throws Exception in case crypto errors occurred.
     */
    @Test(expected = AtpCryptInvalidKeyException.class)
    public void testCreateDefaultAesDecryptorExpectExceptionWhenKeyIsNotValid() throws Exception {
        AtpCryptoFactory.createDefaultAesDecryptor("Invalid");
    }

    /**
     * Test of Default RSA Decryptor creation in case key is not valid.
     *
     * @throws Exception in case crypto errors occurred.
     */
    @Test(expected = AtpCryptInvalidKeyException.class)
    public void testCreateDefaultRsaDecryptorExpectExceptionWhenKeyIsNotValid() throws Exception {
        AtpCryptoFactory.createDefaultRsaDecryptor("Invalid");
    }

}
