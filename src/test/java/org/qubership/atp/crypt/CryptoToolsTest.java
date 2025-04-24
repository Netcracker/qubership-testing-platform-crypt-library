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

import org.junit.Test;

public class CryptoToolsTest {

    private static final String UNENCRYPTED_DATA = "Not encrypted text";
    private static final String ENCRYPTED_DATA =
            "{ENC}{SQlLQ8SeZ5YpsNHL}{SQlLQ8SeZ5YpsNHLZ8Wkf+ku3Lls485XJJDcNX2id6Ym6zwScta" +
                    "+fGheVULW3o2au1vrWkf08K5mjUs4xibnJRaKv2Fff0RvT5oe2QGYPC9asu2imP5ZMtPQfvkNW9A4AuyDQLtTXCENa0zER33VregFmoromc8jzIP486XnZqkHCxOc3J7wz8+jWW4QDG7Ya7qafWhwuXhPc9J8yPqXn7ASfV4EKhev+1MjDD6n2Es4IXKO9f5UksmWP22yikTij2nqjAu5mYVuW/0OzGTslBJ+FdUH0OmCPsIajjRyzcDIeUkb0GPGsH72cnv3ysx1nPdnFkQyR2jycuX5GcTONQ==}";

    @Test
    public void maskEncryptedData_whenNullData() {
        String maskedData = CryptoTools.maskEncryptedData(null);
        assertEquals(null, maskedData);
    }


    @Test
    public void maskEncryptedData_whenEmptyData() {
        String maskedData = CryptoTools.maskEncryptedData("");
        assertEquals("", maskedData);
    }

    @Test
    public void maskEncryptedData_whenNotEncrypted() {
        String maskedData = CryptoTools.maskEncryptedData(UNENCRYPTED_DATA);
        assertEquals(UNENCRYPTED_DATA, maskedData);
    }


    @Test
    public void maskEncryptedData_whenEncrypted() {
        String maskedData = CryptoTools.maskEncryptedData(ENCRYPTED_DATA);
        assertEquals(Constants.ENCRYPTED_MASK, maskedData);
    }
}
