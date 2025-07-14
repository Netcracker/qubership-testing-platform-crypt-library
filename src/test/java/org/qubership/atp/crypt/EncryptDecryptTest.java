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

import static org.junit.Assert.assertEquals;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.qubership.atp.crypt.api.CryptoProvider;
import org.qubership.atp.crypt.api.Decryptor;
import org.qubership.atp.crypt.api.Encryptor;
import org.qubership.atp.crypt.api.KeyEntity;
import org.qubership.atp.crypt.exception.AtpCryptInvalidKeyException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class EncryptDecryptTest {

    private static final String TEMPLATE_FOR_TEXT_WITH_ENCRYPTED_DATA = "{\n"
            + "    \"testPlans\": [\n"
            + "        {\n"
            + "            \"id\": \"98285f56-69e2-4a8a-95ca-2c7ed9260ba9\",\n"
            + "            \"name\": \"test\"\n"
            + "        },\n"
            + "        {\n"
            + "            \"id\": \"cb47eb26-0cd2-49e2-a756-71349112adde\",\n"
            + "            \"name\": \"ENCRYPTED_DATA_1\"\n"
            + "        }\n"
            + "    ],\n"
            + "    \"testCases\": [  \"ENCRYPTED_DATA_2\"  ]\n"
            + "}";

    @Before
    public void setUp() {
    }

    @Test
    public void encryptAndDecryptSuccess() throws Exception {
        encryptDecryptCheck(false);
    }

    @Test
    public void encryptAndDoubleDecryptSuccess() throws Exception {
        encryptDecryptCheck(true);
    }

    private void encryptDecryptCheck(boolean checkDoubleDecrypt) throws Exception {
        CryptoProvider provider = AtpCryptoFactory.getDefaultProvider();
        KeyEntity keys = provider.generateKeys();

        log.info("key: {}\npublic key: {}\nprivate key: {}", keys.getKey(), keys.getPublicKey(), keys.getPrivateKey());

        Encryptor encryptor = AtpCryptoFactory.createEncryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()), provider);
        Decryptor decryptor = AtpCryptoFactory.createDecryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()), provider);

        String textToEncrypt = "Hello World";
        String textEncrypted = encryptor.encrypt(textToEncrypt);
        String textDecrypted = decryptor.decrypt(textEncrypted);
        log.info("Source string: {}\nEncrypted: {}\nDecrypted: {}", textToEncrypt, textEncrypted, textDecrypted);

        Assert.assertEquals(textToEncrypt, textDecrypted);

        if (checkDoubleDecrypt) {
            String textDecrypted2 = decryptor.decryptIfEncrypted(textDecrypted);
            log.info("After the 2nd decrypt {}", textDecrypted2);
            Assert.assertEquals(textDecrypted2, textDecrypted);
        }
    }

    @Test
    public void encryptAndDecrypt_maskEncryptedData_twoEntriesInJson_success() throws Exception {
        CryptoProvider provider = AtpCryptoFactory.getDefaultProvider();
        KeyEntity keys = provider.generateKeys();

        Encryptor encryptor = AtpCryptoFactory.createEncryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()), provider);

        String textToEncrypt1 = "Hello World 1";
        String textToEncrypt2 = "Hello World 2";

        String textEncrypted1 = encryptor.encrypt(textToEncrypt1);
        String textEncrypted2 = encryptor.encrypt(textToEncrypt2);

        String textWithEncryptedData = TEMPLATE_FOR_TEXT_WITH_ENCRYPTED_DATA;
        textWithEncryptedData = textWithEncryptedData
                .replace("ENCRYPTED_DATA_1", textEncrypted1)
                .replace("ENCRYPTED_DATA_2", textEncrypted2);

        log.info("1. before mask \n\n{}\n\n", textWithEncryptedData);

        String maskedText = CryptoTools.maskEncryptedData(textWithEncryptedData);
        log.info("2. after mask \n\n{}\n\n", maskedText);
    }

    @Test(expected = AtpCryptInvalidKeyException.class)
    public void encryptAndDecrypt_providerThrowsException_noDetailsInRethrownException() throws Exception {
        AtpCryptoFactory.createDefaultAesEncryptor("Invalid key");
    }

    public static String opensslKey = "zJ/cEJYuehdjMm3H9HiIWdcHtoby6jbeVShIJtiZ0Lw=";

    private final String commonDecryptedValue = "PLU2JtBeODrJtvE4XJlajG/mqHMDzKDBB6utuf09ZjM=";

    private final String commonEncryptedValue =
            "{ENC}{}{ThRnl0uWjlbB+AjTz5nHupYKK0yuTONGgPV75Ncw2CVEI0NW3m5oh1nA"
            + "/VVZR3DdZSEiHDmJTeElfCJifZ4Osp+aGFbJpQQ+ZMpzpSEaELKIj83wsNFOsGMHhTRq7Wd71MMB"
            + "LjUiFTet1lQi7r/G86THq52wPMgZNAaGA5qpgl58Qh7AYqpeputKL6xIZl4ZGpPiF4VvVYRj5bd3"
            + "hChv/HCP12MowkBaS8Q8BmeIglH1SY8Lh40rgFRHh7MbkXfRdrOBJVLZjfLy+qtynT5cMeBWtpWn"
            + "XPOvKHkZDI2tLt8WgnLOMPtuYrZ2RykpTZLOfiLt1bfEAxwzVaZzPbTb2g==}";

    private final String commonPrivateKey =
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOKzTpRINeYpQExc"
            + "oZImtimGdZSr+hIZ6B7i+DNjGBonnwn4p6x8D93efae3Pza58TMnuhZ/2btGToyWw4TTQ+YzQtfP"
            + "pDW/EV9plCqCQbj9AcWOkRp8EJar63SqkbrWA5Bh54fJUAVhPzsoTLWTXbtBylWs2UVhTiB5ZtEe"
            + "7U8Ezma8J6IjJ2cqFZBUQwca7S7m65kCpV2E6ZmAHu82es366ycdlNRarLUx8V32oeKggwxrznL4"
            + "WqfrE9LwNyU6Z0gqApzS44EqeLeh3t9M46m73m83ZygQiMOcUmosYS7qK79kI7pImkSxFtqvZU0y"
            + "FGJ8ZZxgRZLXkVjm7ElsNdAgMBAAECggEAL4CNBGIg0pJsAF2CHyBrFaB/z3cFiB6y4sT6dYT7Cx"
            + "9gcSyRP5Deyp9iWFixcpiNYmLzUVEggcuipHAkWySOsQEyeHifQP3iImlbDpynFSKhlKZ3rPW16H"
            + "GL17eAFzxvOzRJuQEbY6RxnGi5aBD589Ef+IlfbJoY3atZ4W+MU8tQITyro9sgvc+eYzcUhymyPz"
            + "51hsLVKQUkNISGNgJIhYRplKhZc0639K6YrtrPPrrSsjvcpV03+k7m9Oc9tS/zDQkZHAJgz3DtoK"
            + "QItzGD65i3sH2c3mCLThrmWWvtF/12XugvH8MSbgh1ura5ZlnGa79MXORwX9Q8BHFq9YVJgQKBgQ"
            + "Dzckue6d0Ms+GFz1G+DsHmD0KxXSwgkD3qtbbbDjjhpv3Hw7j271nHWX2bun6ctR0cEcVm0Jp7Oj"
            + "9RS6rlB0klns7Y6TbrCXnMQTNpIT04T9bWY6oIMi2oVPV3wt0aJvHYhS03Pw+aWad/AeSJ7eFzED"
            + "62lFj/JPvRPNPGoUIDtQKBgQDYzNA9DYtkrRBBq2FWSMcoByJm8ce6F56kSS6eHuf79LWia/Fn5k"
            + "suL71HuSyeDLhD/ao2q1XzUlw+Chhz7M9dazsZj3bIVsga8QEJphfC/rIhvrz2scFpDf+H1ydq45"
            + "pZ1sjOFw9e5UZmFZM4tY4dmqdY8JwyopX0vKErLHtaCQJ/DVAy0n33mLo9mxO7ZKlp8Srkes6dmy"
            + "pIOI23ckNU2QJI3qPVeaudPUmnlNyeD/PXo7FVGkpOKG8HB2sb7Wp4lZYZucMHPdNG1eS66wTmVC"
            + "4Jka/hnJEh7hK3WdVOQh/fGfgugNbyA37jqg5wcRqRObmptFJoi4t6OfcZncMz2QKBgQC2QrluGk"
            + "ztvnDERIf4Ogb0J8tMMEdwsxqzkrKWS/VLZFauzYCNkJXzpj7CZXKVDKx8vGy0uSXxAXR605HrI1"
            + "LRfqyYuHtrwUlJHQN6UR/41pZ6uBe0bYvj/ditIrwIqH/Ct0bpu4k4hhfBCrJSIo/vY2z84IrwJq"
            + "9aqJn16ddpwQKBgQCswDP9MCAvUREersEawsji2r8fex0tJz6n10AGHbuv+f69ax3hDrrEJ3b4cy"
            + "PRbOBk1GOmZTk0IUo+RyzrZmdBXRpMUmCwm+48MqiRRp2P5yYaDmKApKq5TbXXfMOd5v2Y0xfg/j"
            + "4DjhT9xVI9c8KhiklDUaIcyq3v4oWQDKVq+Q==";

    @Test
    public void encryptAndDecrypt_opensslGeneratedKey_success() throws Exception {
        String textToEncrypt = "Hello World";
        log.info("1. before encrypt {}", textToEncrypt);

        Encryptor encryptor = AtpCryptoFactory.createDefaultAesEncryptor(opensslKey);
        String textEncrypted = encryptor.encrypt(textToEncrypt);
        log.info("2. after encrypt {}", textEncrypted);

        Decryptor decryptor = AtpCryptoFactory.createDefaultAesDecryptor(opensslKey);
        String textDecrypted = decryptor.decrypt(textEncrypted);
        log.info("3. after decrypt {}", textDecrypted);
        Assert.assertEquals(textToEncrypt, textDecrypted);
    }

    @Test
    public void encryptAndDecrypt_usingEncryptedAESKey() throws Exception {
        Decryptor rsaDecryptor = AtpCryptoFactory.createDefaultRsaDecryptor(commonPrivateKey);
        String key = rsaDecryptor.decrypt(commonEncryptedValue);
        log.info("Decrypted key = {}", key);
        assertEquals(commonDecryptedValue, key);

        String string = "Hello World";
        Encryptor aesEncryptor = AtpCryptoFactory.createDefaultAesEncryptor(key);
        String encryptedString = aesEncryptor.encrypt(string);
        log.info("Encrypted string = {}", key);

        Decryptor aesDecryptor = AtpCryptoFactory.createDefaultAesDecryptor(key);
        String decryptedString = aesDecryptor.decrypt(encryptedString);
        log.info("Decrypted string = {}", decryptedString);
        assertEquals(string, decryptedString);
    }

    @Test
    public void decryptText_haveTwoEncryptedValueInText_gotDecryptedText() throws Exception {
        Decryptor rsaDecryptor = AtpCryptoFactory.createDefaultRsaDecryptor(commonPrivateKey);
        String text = "Encrypted text: " + commonEncryptedValue + "\n Test:" + commonEncryptedValue;
        String expected = "Encrypted text: " + commonDecryptedValue + "\n Test:" + commonDecryptedValue;
        String actual = rsaDecryptor.decryptEncryptedPlacesInString(text);
        assertEquals(expected, actual);
    }
}
