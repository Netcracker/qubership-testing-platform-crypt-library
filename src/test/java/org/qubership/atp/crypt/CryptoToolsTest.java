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
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class CryptoToolsTest {

    private static final String UNENCRYPTED_DATA = "Not encrypted text";

    @Test
    public void maskEncryptedData_whenNullData() {
        String maskedData = CryptoTools.maskEncryptedData(null);
        assertNull(maskedData);
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

}
