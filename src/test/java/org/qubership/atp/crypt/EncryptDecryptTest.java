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
    public void setUp() throws Exception {
    }

    @Test
    public void encryptAndDecrypt_success() throws Exception {
        CryptoProvider provider = AtpCryptoFactory.createBouncyCastleProvider();
        KeyEntity keys = provider.generateKeys();

        log.info("key {}", keys.getKey());
        log.info("public key {}", keys.getPublicKey());
        log.info("private key {}", keys.getPrivateKey());

        String textToEncrypt = "Hello World";
        log.info("1. before encrypt {}", textToEncrypt);

        Encryptor encryptor = AtpCryptoFactory.createEncryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()),
                provider);
        String textEncrypted = encryptor.encrypt(textToEncrypt);
        log.info("2. after encrypt {}", textEncrypted);

        Decryptor decryptor = AtpCryptoFactory.createDecryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()),
                provider);
        String textDecrypted = decryptor.decrypt(textEncrypted);
        log.info("3. after decrypt {}", textDecrypted);

        Assert.assertEquals(textToEncrypt, textDecrypted);
    }


    @Test
    public void encryptAndDoubleDecrypt_success() throws Exception {
        CryptoProvider provider = AtpCryptoFactory.createBouncyCastleProvider();
        KeyEntity keys = provider.generateKeys();

        log.info("key {}", keys.getKey());
        log.info("public key {}", keys.getPublicKey());
        log.info("private key {}", keys.getPrivateKey());

        String textToEncrypt = "Hello World";
        log.info("1. before encrypt {}", textToEncrypt);

        Encryptor encryptor = AtpCryptoFactory.createEncryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()),
                provider);
        String textEncrypted = encryptor.encrypt(textToEncrypt);
        log.info("2. after encrypt {}", textEncrypted);

        Decryptor decryptor = AtpCryptoFactory.createDecryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()),
                provider);
        String textDecrypted = decryptor.decrypt(textEncrypted);
        log.info("3. after decrypt {}", textDecrypted);

        String textDecrypted2 = decryptor.decryptIfEncrypted(textDecrypted);
        log.info("4. after second decrypt {}", textDecrypted2);

        Assert.assertEquals(textToEncrypt, textDecrypted);
        Assert.assertEquals(textDecrypted2, textDecrypted);
    }

    @Test
    public void encryptAndDecrypt_maskEncryptedData_twoEntriesInJson_success() throws Exception {
        CryptoProvider provider = AtpCryptoFactory.createBouncyCastleProvider();
        KeyEntity keys = provider.generateKeys();

        Encryptor encryptor = AtpCryptoFactory.createEncryptor(Constants.AES_TRANSFORMATION,
                provider.readKey(keys.getKey()),
                provider);

        String textToEncrypt1 = "Hello World 1";
        String textToEncrypt2 = "Hello World 2";

        String textEncrypted1 = encryptor.encrypt(textToEncrypt1);
        String textEncrypted2 = encryptor.encrypt(textToEncrypt2);

        String textWithEncryptedData = TEMPLATE_FOR_TEXT_WITH_ENCRYPTED_DATA;
        textWithEncryptedData = textWithEncryptedData
                .replace("ENCRYPTED_DATA_1", textEncrypted1).replace("ENCRYPTED_DATA_2", textEncrypted2);

        log.info("1. before mask \n\n{}\n\n", textWithEncryptedData);

        String maskedText = CryptoTools.maskEncryptedData(textWithEncryptedData);
        log.info("2. after mask \n\n{}\n\n", maskedText);
    }

    @Test(expected = AtpCryptInvalidKeyException.class)
    public void encryptAndDecrypt_providerThrowsException_noDetailsInRethrownException() throws Exception {
        AtpCryptoFactory.createDefaultAesEncryptor("Invalid key");
    }

    public static String opensslKey = "zJ/cEJYuehdjMm3H9HiIWdcHtoby6jbeVShIJtiZ0Lw=";

    public static String opensslPubKey =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzrGalw6ZAssafDrg7im3Hyw5YgWg+Ym2+cIa9Kt9Ceo0qpJFHmTI8RJCy8rsfQQu5DuPuM+wk4chsZCv1JyZMkb6Bh04BnLL7XdooAYjmQfK772qPjEDf2VSMK/IQLgC+7WAFR8i7KXuKzVJqRLWLVvM4TmNLXye7rqZ3xIfrjBS8IZVSUg7cy8mwDBzxSYt7Hs3RHLVGSDx9DUtt3dHrW95cjPVKQWB7cbrpK3b4wRhAXBOkjWJlRz9qZahNCPY8GzV6cxMTfzgCTo90Bd7At7Ma6mLKZaOj25eEhBKt/ac4OP2TobvVSMJJQrrpjI74M4rzoXc+pvQY+8rLSwyxwIDAQAB";

    public static String opensslPrivKey =
            "-----BEGIN RSA PRIVATE KEY-----\n"
                    + "MIIEowIBAAKCAQEAzrGalw6ZAssafDrg7im3Hyw5YgWg+Ym2+cIa9Kt9Ceo0qpJF\n"
                    + "HmTI8RJCy8rsfQQu5DuPuM+wk4chsZCv1JyZMkb6Bh04BnLL7XdooAYjmQfK772q\n"
                    + "PjEDf2VSMK/IQLgC+7WAFR8i7KXuKzVJqRLWLVvM4TmNLXye7rqZ3xIfrjBS8IZV\n"
                    + "SUg7cy8mwDBzxSYt7Hs3RHLVGSDx9DUtt3dHrW95cjPVKQWB7cbrpK3b4wRhAXBO\n"
                    + "kjWJlRz9qZahNCPY8GzV6cxMTfzgCTo90Bd7At7Ma6mLKZaOj25eEhBKt/ac4OP2\n"
                    + "TobvVSMJJQrrpjI74M4rzoXc+pvQY+8rLSwyxwIDAQABAoIBAQCEONEvuMLhKpQy\n"
                    + "zGd/c2gVpPDAZ+FmQFawxx7/TYSbhxtR0mgs3UQ+EvRv8cv+3WIx1nhGPXYzqcpA\n"
                    + "ENKqK9NEemsO5jokxeL2ceCYHdU/2+BSJP528lvObz54rrpnzE78PktFN7nbsPn+\n"
                    + "4gPRCJ/CPGt/2JUbeBEjnnM4ZBuoDVNqm4CQehQDyI5m8hBWFjQ1nY6P78ThgJSN\n"
                    + "XsKgDXUe7uS2qVgeq/T8irs+6jIqqpvP1VcdcYnV2qUElgrGDfQFkMXaRVvGZ8R4\n"
                    + "XlVMQLVkBEudOkQiyWx2/quY0LgNcZc9PUk0n7bER2/PeSX/aONZPrHacYuz1vqs\n"
                    + "1wCWTq0hAoGBAOmUoQGJRwtc0xz01DWozqhw/mSD+ifcmCxCpQOHvG4Z+6Q99zDu\n"
                    + "kF1k/08BE0K21062C8gfVjsCPb2Ld9tmwqXfTIRzBgiDYZcqILOHkyUa5P9J6Ph6\n"
                    + "6+IWXxpMa6N+PJDzY/Ut42Mw6JtqNTGaWL+Yc4gc4+23uMUnMyrJE7KrAoGBAOKI\n"
                    + "VO5Dflbc9PmnA0plSMdubwvfhqSVCsZXV0EUfs5Dxw0tT98eBrf8Yry/g1bHnOxr\n"
                    + "rPoC88eUYi0YXJJ8A9u5umuIDEE6bX6OoE7XUYuvl51MUFTCEz4LUp0Mkmb/ojpX\n"
                    + "uMcnqu1zjDQX1wlmcwFQOxywajtvUwSR/gnV5aBVAoGAKnARjJjnan4T8SfeQl2I\n"
                    + "JnxZC+QamBFxKGF3X5vStWJNIPsNJTvCyOUnqa/1UuKrXaafn11qKlBu7Tggr6EM\n"
                    + "7lwSp+HKD9Pm8DL8PAH+zvgC8Qr5o+OZZbtQzhNiXxL5aBCAcbRDouro6Au03G1B\n"
                    + "gJXvL6SoGLGPhWpo1nYv+P8CgYBf1imIO4mhmg0R6XRc7wihRrk4HrLJwjwyuRSy\n"
                    + "9cbH4Ki/jGH0FLHm+KGVFLit5/kdlFgz1TfpQX9fcKUJW+oN9T9G6uG0XtGf7xsm\n"
                    + "/7UCEaFk7Lo3gXu+je+/fWgapx+s6xvDNab8mhvAli1lTrBs59J6SrBGwMwwbMs6\n"
                    + "wgFJmQKBgDJdQzBJ+7Cn7xm8GiVZ4jcxKTi37mzCldl8/AtmNw2HhIy7gAn1bRt9\n"
                    + "zHPPKU6W0N7uzcRFAvTtRRXSmC40/yDCn8+syW46PMndsZUmYpKJo85OSsfm7uVV\n"
                    + "wmaBdxsKrVjUGS3rn8erDlfOijGP1oa8kEhk0XaTp6yST4285DSC\n"
                    + "-----END RSA PRIVATE KEY-----\n";

    @Test
    public void encryptAndDecrypt_opensslGenratedKey_success() throws Exception {
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
        String decryptedKey = "PLU2JtBeODrJtvE4XJlajG/mqHMDzKDBB6utuf09ZjM=";
        String encryptedKey = "{ENC}{}{ThRnl0uWjlbB+AjTz5nHupYKK0yuTONGgPV75Ncw2CVEI0NW3m5oh1nA"
                + "/VVZR3DdZSEiHDmJTeElfCJifZ4Osp+aGFbJpQQ+ZMpzpSEaELKIj83wsNFOsGMHhTRq7Wd71MMB"
                + "LjUiFTet1lQi7r/G86THq52wPMgZNAaGA5qpgl58Qh7AYqpeputKL6xIZl4ZGpPiF4VvVYRj5bd3"
                + "hChv/HCP12MowkBaS8Q8BmeIglH1SY8Lh40rgFRHh7MbkXfRdrOBJVLZjfLy+qtynT5cMeBWtpWn"
                + "XPOvKHkZDI2tLt8WgnLOMPtuYrZ2RykpTZLOfiLt1bfEAxwzVaZzPbTb2g==}";
        String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOKzTpRINeYpQExc"
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
        Decryptor rsaDecryptor = AtpCryptoFactory.createDefaultRsaDecryptor(privateKey);
        String key = rsaDecryptor.decrypt(encryptedKey);
        System.out.println("Decrypted key = " + key);
        assertEquals(decryptedKey, key);
        String string = "Hello World";
        Encryptor aesEncryptor = AtpCryptoFactory.createDefaultAesEncryptor(key);
        String encryptedString = aesEncryptor.encrypt(string);

        System.out.println("Encrypted string = " + key);

        Decryptor aesDecryptor = AtpCryptoFactory.createDefaultAesDecryptor(key);
        String decryptedString = aesDecryptor.decrypt(encryptedString);
        System.out.println("Decrypted string = " + decryptedString);
        assertEquals(string, decryptedString);
    }


    @Test
    public void decryptText_haveTwoEncryptedValueInText_gotDecryptedText() throws Exception {
        String decryptedValue = "PLU2JtBeODrJtvE4XJlajG/mqHMDzKDBB6utuf09ZjM=";
        String encryptedValue = "{ENC}{}{ThRnl0uWjlbB+AjTz5nHupYKK0yuTONGgPV75Ncw2CVEI0NW3m5oh1nA"
                + "/VVZR3DdZSEiHDmJTeElfCJifZ4Osp+aGFbJpQQ+ZMpzpSEaELKIj83wsNFOsGMHhTRq7Wd71MMB"
                + "LjUiFTet1lQi7r/G86THq52wPMgZNAaGA5qpgl58Qh7AYqpeputKL6xIZl4ZGpPiF4VvVYRj5bd3"
                + "hChv/HCP12MowkBaS8Q8BmeIglH1SY8Lh40rgFRHh7MbkXfRdrOBJVLZjfLy+qtynT5cMeBWtpWn"
                + "XPOvKHkZDI2tLt8WgnLOMPtuYrZ2RykpTZLOfiLt1bfEAxwzVaZzPbTb2g==}";
        String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDOKzTpRINeYpQExc"
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
        Decryptor rsaDecryptor = AtpCryptoFactory.createDefaultRsaDecryptor(privateKey);
        String text = "Encrypted text: " + encryptedValue + "\n Test:" + encryptedValue;
        String expected = "Encrypted text: " + decryptedValue + "\n Test:" + decryptedValue;
        String actual = rsaDecryptor.decryptEncryptedPlacesInString(text);
        assertEquals(expected, actual);
    }
}
