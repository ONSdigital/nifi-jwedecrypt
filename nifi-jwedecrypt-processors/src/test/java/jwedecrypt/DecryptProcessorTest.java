/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jwedecrypt;

import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;


public class DecryptProcessorTest {

    private TestRunner testRunner;
    private ClassLoader classLoader;
    @Before
    public void init() {
        testRunner = TestRunners.newTestRunner(DecryptProcessor.class);
        classLoader = DecryptProcessor.class.getClassLoader();
    }

    @Test
    public void testSuccess() {
        InputStream content = getPayload("encryptedPayload");
        testRunner.setProperty(DecryptProcessor.ENCRYPTION_PRIVATE_KEY_PATH, classLoader.getResource("encryption-private-key.pem").getFile());
        testRunner.setProperty(DecryptProcessor.SIGNING_PUBLIC_KEY_PATH, classLoader.getResource("signing-public-key.pem").getFile());
        testRunner.assertValid();

        testRunner.enqueue(content);

        testRunner.run(1);

        // All results were processed without failure
        testRunner.assertQueueEmpty();

        List<MockFlowFile> results = testRunner.getFlowFilesForRelationship(DecryptProcessor.REL_SUCCESS);
        assertEquals(results.size(), 1);
        MockFlowFile result = results.get(0);
        String resultValue = new String(testRunner.getContentAsByteArray(result));
        JSONObject obj = new JSONObject(resultValue);
        assertEquals(obj.getString("tx_id"), "efba78bc-bccd-4084-b759-8fabcd75d47d");
    }

    @Test(expected = AssertionError.class)
    public void testMissingEncryptionKey() {
        testRunner.setProperty(DecryptProcessor.ENCRYPTION_PRIVATE_KEY_PATH, "some-missing-key.pem");
        testRunner.setProperty(DecryptProcessor.SIGNING_PUBLIC_KEY_PATH, classLoader.getResource("signing-public-key.pem").getFile());
        testRunner.assertNotValid();

        testRunner.enqueue(new ByteArrayInputStream("dummy payload".getBytes()));
        testRunner.run(1);
    }

    @Test(expected = AssertionError.class)
    public void testMissingSigningKey() {
        testRunner.setProperty(DecryptProcessor.ENCRYPTION_PRIVATE_KEY_PATH, classLoader.getResource("encryption-private-key.pem").getFile());
        testRunner.setProperty(DecryptProcessor.SIGNING_PUBLIC_KEY_PATH, "some-missing-key.pem");
        testRunner.assertNotValid();

        testRunner.enqueue(new ByteArrayInputStream("dummy payload".getBytes()));
        testRunner.run(1);
    }

    @Test
    public void testInvalidPayload() {
        InputStream content = getPayload("invalidEncryptedPayload");
        testRunner.setProperty(DecryptProcessor.ENCRYPTION_PRIVATE_KEY_PATH, classLoader.getResource("encryption-private-key.pem").getFile());
        testRunner.setProperty(DecryptProcessor.SIGNING_PUBLIC_KEY_PATH, classLoader.getResource("signing-public-key.pem").getFile());
        testRunner.assertValid();

        testRunner.enqueue(content);

        testRunner.run(1);

        testRunner.assertQueueEmpty();

        List<MockFlowFile> results = testRunner.getFlowFilesForRelationship(DecryptProcessor.REL_FAILURE);
        assertEquals(results.size(), 1);
    }

    private InputStream getPayload(String filename) {
        return classLoader.getResourceAsStream(filename);
    }

}
