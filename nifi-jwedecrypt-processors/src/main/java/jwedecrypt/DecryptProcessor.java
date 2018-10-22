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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


@CapabilityDescription("Decrypts JWE tokens")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class DecryptProcessor extends AbstractProcessor {

    public static final PropertyDescriptor SIGNING_PUBLIC_KEY_PATH = new PropertyDescriptor
            .Builder().name("SIGNING_PUBLIC_KEY_PATH")
            .displayName("Signing public key path")
            .description("Path to the public key of the key used to sign the token")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();

    public static final PropertyDescriptor ENCRYPTION_PRIVATE_KEY_PATH = new PropertyDescriptor
            .Builder().name("ENCRYPTION_PRIVATE_KEY_PATH")
            .displayName("Encryption private key path")
            .description("Path to the private key to use to decrypt the token")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.FILE_EXISTS_VALIDATOR)
            .build();

    static final Relationship REL_SUCCESS = new Relationship.Builder()
            .description("Successfully decrypted payloads go to this relationship.")
            .name("success")
            .build();
    static final Relationship REL_FAILURE = new Relationship.Builder()
            .description("Payloads that cannot be decrypted go to this relationship.")
            .name("failure")
            .build();


    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    private PrivateKey encryptionKey;

    private PublicKey signingKey;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(SIGNING_PUBLIC_KEY_PATH);
        descriptors.add(ENCRYPTION_PRIVATE_KEY_PATH);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);

        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return this.descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
        String encryptionKeyPath = context.getProperty(ENCRYPTION_PRIVATE_KEY_PATH).getValue();
        String signingKeyPath = context.getProperty(SIGNING_PUBLIC_KEY_PATH).getValue();
        loadKeys(encryptionKeyPath, signingKeyPath);
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            getLogger().debug("Empty flow file");
            return;
        }

        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()){
            session.exportTo(flowFile, bos);
            bos.close();

            String jweString = new String(bos.toByteArray());
            byte[] payload = decryptJWE(jweString);
            flowFile = session.write(flowFile, os -> os.write(payload));

            session.transfer(flowFile, REL_SUCCESS);
        } catch (Exception ex) {
            session.transfer(flowFile, REL_FAILURE);
            getLogger().error("Failed to decrypt payload due to {}", ex);
        }
    }

    private byte[] decryptJWE(String jweString) throws ParseException, JOSEException {
        // Parse the JWE string
        JWEObject jweObject = JWEObject.parse(jweString);
        getLogger().debug("JWE successfully parsed.");

        // Decrypt with private key
        jweObject.decrypt(new RSADecrypter(encryptionKey));
        getLogger().debug("JWE successfully decrypted.");

        // Extract payload
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey)signingKey);

        if (!signedJWT.verify(verifier)) {
            throw new JWTVerificationException();
        }

        getLogger().debug("JWT signature verification succeeded.");

        return signedJWT.getPayload().toBytes();
    }

    private void loadKeys(String encryptionKeyPath, String signingKeyPath) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");

            this.encryptionKey = generatePrivateKey(factory, encryptionKeyPath);
            getLogger().info("Encrypt key file loaded");

            this.signingKey = generatePublicKey(factory, signingKeyPath);
            getLogger().info("Signing key file loaded");

        } catch (IOException | GeneralSecurityException ex) {
            getLogger().error("Error loading keys", ex);
        }
    }

    private static PrivateKey generatePrivateKey(KeyFactory factory, String filename) throws InvalidKeySpecException, IOException {
        byte[] content = readPemFileContent(filename);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(content);
        return factory.generatePrivate(pkcs8EncodedKeySpec);
    }

    private static PublicKey generatePublicKey(KeyFactory factory, String filename) throws InvalidKeySpecException, IOException {
        byte[] content = readPemFileContent(filename);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(content);
        return factory.generatePublic(x509EncodedKeySpec);
    }

    private static byte[] readPemFileContent(String filename) throws IOException {
        PemFile pemFile = new PemFile(filename);
        return pemFile.getPemObject().getContent();
    }
}
