/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.android.legacy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import com.android.identity.android.securearea.AndroidKeystoreSecureArea;
import com.android.identity.android.storage.AndroidStorageEngine;
import com.android.identity.credential.NameSpacedData;
import com.android.identity.internal.Util;
import com.android.identity.securearea.SecureArea;
import com.android.identity.securearea.SecureAreaRepository;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.CborUtil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;

@SuppressWarnings("deprecation")
public class MigrateFromKeystoreICStoreTest {
    private static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
    private static final String MDL_NAMESPACE = "org.iso.18013.5.1";
    private static final String AAMVA_NAMESPACE = "org.iso.18013.5.1.aamva";
    private static final String TEST_NAMESPACE = "org.example.test";

    // The two methods that can be used to migrate a credential from KeystoreIdentityCredentialStore
    // to CredentialStore are getNamedSpacedData() and getCredentialKey(). This test checks that
    // they work as expected..
    //
    @Test
    public void testMigrateToCredentialStore() throws Exception {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        File storageDir = new File(context.getDataDir(), "ic-testing");
        StorageEngine storageEngine = new AndroidStorageEngine.Builder(context, storageDir).build();
        AndroidKeystoreSecureArea aksSecureArea = new AndroidKeystoreSecureArea(context, storageEngine);
        IdentityCredentialStore icStore = Utility.getIdentityCredentialStore(context);

        AccessControlProfile noAuthProfile =
                new AccessControlProfile.Builder(new AccessControlProfileId(0))
                        .setUserAuthenticationRequired(false)
                        .build();
        Collection<AccessControlProfileId> ids = new ArrayList<AccessControlProfileId>();
        ids.add(new AccessControlProfileId(0));

        byte[] encodedDrivingPrivileges = Util.cborEncode(
                new CborBuilder()
                        .addArray()
                        .addMap()
                        .put(new UnicodeString("vehicle_category_code"), new UnicodeString("A"))
                        .end()
                        .end()
                        .build().get(0));

        PersonalizationData personalizationData =
                new PersonalizationData.Builder()
                        .addAccessControlProfile(noAuthProfile)
                        .putEntry(MDL_NAMESPACE, "given_name", ids, Util.cborEncodeString("Erika"))
                        .putEntry(MDL_NAMESPACE, "family_name", ids, Util.cborEncodeString("Mustermann"))
                        .putEntry(MDL_NAMESPACE, "resident_address", ids, Util.cborEncodeString("Germany"))
                        .putEntry(MDL_NAMESPACE, "portrait", ids, Util.cborEncodeBytestring(new byte[]{0x01, 0x02}))
                        .putEntry(MDL_NAMESPACE, "height", ids, Util.cborEncodeNumber(180))
                        .putEntry(MDL_NAMESPACE, "driving_privileges", ids, encodedDrivingPrivileges)
                        .putEntry(AAMVA_NAMESPACE, "weight_range", ids, Util.cborEncodeNumber(5))
                        .putEntry(TEST_NAMESPACE, "neg_int", ids, Util.cborEncodeNumber(-42))
                        .putEntry(TEST_NAMESPACE, "int_16", ids, Util.cborEncodeNumber(0x101))
                        .putEntry(TEST_NAMESPACE, "int_32", ids, Util.cborEncodeNumber(0x10001))
                        .putEntry(TEST_NAMESPACE, "int_64", ids, Util.cborEncodeNumber(0x100000001L))
                        .build();
        String credName = "test";
        icStore.deleteCredentialByName(credName);
        WritableIdentityCredential wc = icStore.createCredential(credName, MDL_DOCTYPE);
        Collection<X509Certificate> wcCertChain = wc.getCredentialKeyCertificateChain("".getBytes(StandardCharsets.UTF_8));
        PublicKey credentialKeyPublic = wcCertChain.iterator().next().getPublicKey();
        wc.personalize(personalizationData);

        KeystoreIdentityCredential cred = (KeystoreIdentityCredential) icStore.getCredentialByName(
                credName,
                IdentityCredentialStore.CIPHERSUITE_ECDHE_HKDF_ECDSA_WITH_AES_256_GCM_SHA256);
        Assert.assertNotNull(cred);

        // Get and check NameSpacedData
        NameSpacedData nsd = cred.getNameSpacedData();
        Assert.assertEquals(
                "{\n" +
                        "  \"org.iso.18013.5.1\": {\n" +
                        "    \"given_name\": 24(<< \"Erika\" >>),\n" +
                        "    \"family_name\": 24(<< \"Mustermann\" >>),\n" +
                        "    \"resident_address\": 24(<< \"Germany\" >>),\n" +
                        "    \"portrait\": 24(<< h'0102' >>),\n" +
                        "    \"height\": 24(<< 180 >>),\n" +
                        "    \"driving_privileges\": 24(<< [\n" +
                        "      {\n" +
                        "        \"vehicle_category_code\": \"A\"\n" +
                        "      }\n" +
                        "    ] >>)\n" +
                        "  },\n" +
                        "  \"org.iso.18013.5.1.aamva\": {\n" +
                        "    \"weight_range\": 24(<< 5 >>)\n" +
                        "  },\n" +
                        "  \"org.example.test\": {\n" +
                        "    \"neg_int\": 24(<< -42 >>),\n" +
                        "    \"int_16\": 24(<< 257 >>),\n" +
                        "    \"int_32\": 24(<< 65537 >>),\n" +
                        "    \"int_64\": 24(<< 4294967297 >>)\n" +
                        "  }\n" +
                        "}", CborUtil.toDiagnostics(nsd.encodeAsCbor(),
                CborUtil.DIAGNOSTICS_FLAG_PRETTY_PRINT | CborUtil.DIAGNOSTICS_FLAG_EMBEDDED_CBOR));

        String credentialKeyAlias = cred.getCredentialKeyAlias();
        aksSecureArea.createKeyForExistingAlias(credentialKeyAlias);

        // Check that CrendentialKey's KeyInfo is correct
        AndroidKeystoreSecureArea.KeyInfo keyInfo = aksSecureArea.getKeyInfo(credentialKeyAlias);
        Assert.assertNotNull(keyInfo);
        Assert.assertTrue(keyInfo.getAttestation().size() >= 1);
        Assert.assertEquals(SecureArea.KEY_PURPOSE_SIGN, keyInfo.getKeyPurposes());
        Assert.assertEquals(SecureArea.EC_CURVE_P256, keyInfo.getEcCurve());
        Assert.assertTrue(keyInfo.isHardwareBacked());
        Assert.assertFalse(keyInfo.isStrongBoxBacked());
        Assert.assertFalse(keyInfo.isUserAuthenticationRequired());
        Assert.assertEquals(0, keyInfo.getUserAuthenticationTimeoutMillis());
        Assert.assertEquals(0, keyInfo.getUserAuthenticationType());
        Assert.assertNull(keyInfo.getAttestKeyAlias());
        Assert.assertNull(keyInfo.getValidFrom());
        Assert.assertNull(keyInfo.getValidUntil());

        // Check that we can use CredentialKey via AndroidKeystoreSecureArea...
        byte[] dataToSign = new byte[]{1, 2, 3};
        byte[] derSignature = aksSecureArea.sign(
                credentialKeyAlias,
                SecureArea.ALGORITHM_ES256,
                dataToSign,
                null);
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(credentialKeyPublic);
            signature.update(dataToSign);
            Assert.assertTrue(signature.verify(derSignature));
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }
}
