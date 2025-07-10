# Qubership Testing Platform Crypt Library

## How to generate the pair key for BouncyCastleProvider

### Windows

```bash
java -cp atp-crypt-0.0.7.jar;slf4j-api-1.7.25.jar;bcprov-jdk15to18-1.68.jar;commons-lang-2.5.jar org.qubership.atp.crypt.KeyPairGenerator
```

### Linux

```bash
java -cp atp-crypt-0.0.7.jar:slf4j-api-1.7.25.jar:bcprov-jdk15to18-1.68.jar:commons-lang-2.5.jar org.qubership.atp.crypt.KeyPairGenerator
```

Output will be similar to
```text
key=some-key-value
encryptedKey={ENC}{}{some-encrypted-value==}
publicKey=some-public-key
privateKey=some-private-key
```
where
- **key** is AES256 raw key
- **encryptedKey** is AES256 key which is ecnrypted by RSA2048 public key
- **publicKey** is RSA2048 public key
- **privateKey** is RSA2048 private key

## How to generate RSA key pair and encrypt existing AES key using them
```bash
java -cp atp-crypt-0.0.7.jar;slf4j-api-1.7.25.jar;bcprov-jdk15to18-1.68.jar;commons-lang-2.5.jar org.qubership.atp.crypt.KeyPairGenerator <AES256 raw key>
```

## How to generate the pair key using openssl

### RSA Private key
```bash
openssl genrsa -out private.pem 2048
```

### RSA Public key
```bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

### AES key
```bash
openssl TBD
```

## How to use as library in your service

Add dependency
```xml
<dependency>
    <groupId>org.qubership.atp</groupId>
    <artifactId>atp-crypt</artifactId>
    <version>0.0.7</version>
</dependency>
```

### Working with Spring framework

Add the following properties to you application.properties file

```text
atp.crypto.key=<encryptedKey>
atp.crypto.privateKey=<privateKey>
```

for example
```text
atp.crypto.key=${ATP_CRYPTO_KEY:{ENC}{}{Sck4jAe1F2+uknItF3x4gS6jKaghLUPaYL9+FCip8xxB0R/3vfzbG70rBrC7/utroXr4bdyzICWTxJ+mQHZwBCcEt0JENU1rwoN2z9Y9Q/hfL6agLYSxuc1w2yFMM8MU8fJyrA5586cfMtCi3f5wHzh7WljjcsB8J6CptbCKC7PNoIdAa8VX2DhvRIReWsLrhhe1bbzl/GhqhqIf9Gr2CALUsAZwnv+NyfjTVExuWJWdDP0BS8gnlAlVJyQZGiYJmrsNsNRhC1Rhhg59jvDv9sm+zBUw81G62w+JJP+36XOnRIuuSC6RxckrypQFM04a+XolV6KuhShhoW+zv2IlwQ==}}
atp.crypto.privateKey=${ATP_CRYPTO_PRIVATE_KEY:MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCSs7+T9jYks2wplAIkKZAQZWSzD6sDnfNnkkAHAe4eh1E4OQDyc+Gay11QCxaM0VFwl3JHeFst/fXYMJNsAh7kX00arNDb6QXABoilKDtFY4FPzXJlG6JmLjzJhREl2cH4V5mar1Wb7NQgWeHOBOfYnnwsKUKMI2wRgEhJnkQl5cFFElGikanyAPTq1YTfLVG3ijXDVzI/acSCv/FPEVlyXB0TpolkIOY5KWkDRkNN28Q22ED1CWAw7NV8o9Hgmo+z1gwSDk75ms9zpS/P38LMj0aqhC0ixzQ+WFmf5ODGAE+kShk3JZ7rUmj4PewnyfdAxE6ib80t0z23J1dm8TLdAgMBAAECggEAZ04YjFMHEZUfh6/oShrSjhk4bjeMT8G8k6STXdvoGKtlcFgD6LfdmKm4jhMg0AzecpDTMqz4WEzMAG9EgPyFUIAjxbMIaLORDwYK13KbOmO1vcKI2dY56AaLW8VOq/7J7t2RFzJ88I43Woiwz+j4crw36MktSY3wHerd/Klsh9pO0bPjGLQsSEcJk6BiEjB+hVqBSZa3ioA4uvTP48Tr8T+eLTNu81NI4XeibwmRypyUr4FrAYLubMOYoIO2H9XC68dO6whjmiJ3UeAE/TQ31OipZz74vzwNuT0zYLo3kWqxVesLp1ia/q9nqjYinXqcDJIv1fEBZU5BE4NsgZPZwQKBgQDUEZQy0k1Si+gafcFFBfxnGpnDWSosAgi7ytXvt8Y2YNo3VgNOZ1ykf9bqZezckMo2kPcy5CUEjQHxzjGqq+Ot5qYMyfh0vZ/h8X89IVPxwiDylPhUU0QNk4G9X8Sbw8z+z6tb98++wYbtVCcYFeYNZ4MWYI1usjfBpkYPZYZ/CQKBgQCxF6c7M1IPPUB15bfhWv2ihf2Z5hC/+/JIytUT54XOFd6xZ5TlUwudJcQIpUruCDJilzZBicaA8N4AUKoNtr1eNDf1gXJO+eyyZXN4SH6WIpSXP9MMxmNtX/3H356NyfkqpAZtteMjDfIwW4L7UtF0iuI0zmvxCUhxJoWqLyU2NQKBgFiANY64ARjP1j8n9/4sL1d/3GeP0G+pMafdUEbINOoApVCujparwBfOWgxcGOs7aYg4G1GbsG8jwYn9+PA2579tICL6LrvZXt3WALmsLPIZh9J0pOXcEexwgJZdXxl6LxSv6d1pn8MF1J86nU4J5YX2ithN1vg5W9du4pIOVoCxAoGBAJfVzd4mLE9Alwn+gV/IYfp8o2jWJrpUS/E5ZuN/9+swORUl2DWetDBydtdq0QmxIXICb9RVSkq3OcBPaN4FNeuVHf1ylQ09n0F9Vjlk/pO+5mOfp1YmqozWZoJ+KjUrXGTA6XobHrmpdWMcsvrEkS04/qWD7mxlJyVMgAHgFimZAoGBANIatOQqXT3i4rfvfN8JeFA0RbOAFXqbMb8Ty0IhVEdvj4MNYhRwmaFnW/my2WQcldufGM5FjWbSc4/cEuVp1q4ybhQ8q3XbZQpdRrt5PlZPxgN7ctxTcTI67d7/I+Rf6io+fKaOrPnxHdJqjQj9kNbYG5iAZ20GbR7aCGVuKEaE}
```

Add **@AtpCryptoEnable** annotation to Main class to initialize Encryptor bean.

For encryption:
- Use autowired bean to encrypt (**org.qubership.atp.crypt.api.Encryptor**)

Add **@AtpDecryptorEnable** annotation to Main class to initialize Decryptor bean.

For decryption:
- Use autowired bean to decrypt (**org.qubership.atp.crypt.api.Decryptor**)

### Working without Spring framework

In case there is no Spring framework in application, use **org.qubership.atp.crypt.AtpCryptoFactory** for initializing required objects.

Example:
```java
String textToEncrypt = "Hello World";

CryptoProvider provider = AtpCryptoFactory.createBouncyCastleProvider();
KeyEntity keys = provider.generateKeys();

// encrypting using AES256 key
Encryptor encryptor = AtpCryptoFactory.createDefaultAesEncryptor(keys.getKey(), provider);
String ecryptedText = encryptor.encrypt(textToEncrypt);

// decrypting using AES256 key
Decryptor decryptor = AtpCryptoFactory.createDefaultAesDecryptor(keys.getKey());
String decryptedText = decryptor.decrypt(ecryptedText);
```

```java
// Encryption and decryption using RSA keys
String publicKey = "some-public-key";
String privateKey = "some-private-key";

String textToEncrypt = "Hello World";

// encrypting
Encryptor encryptor = AtpCryptoFactory.createDefaultRsaEncryptor(publicKey);
String ecryptedText = encryptor.encrypt(textToEncrypt);

// decrypting
Decryptor decryptor = AtpCryptoFactory.createDefaultRsaDecryptor(privateKey);
String decryptedText = decryptor.decrypt(ecryptedText);
```

### Mask encrypted data
```java
String maskedData = CryptoTools.maskEncryptedData(sensitiveData);
```
