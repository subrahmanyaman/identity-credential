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
package com.android.identity.android.direct_access;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.security.keystore.KeyProperties;
import androidx.annotation.NonNull;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import com.android.identity.android.legacy.AccessControlProfile;
import com.android.identity.android.legacy.AccessControlProfileId;
import com.android.identity.android.legacy.PersonalizationData;
import com.android.identity.internal.Util;
import com.android.identity.mdoc.request.DeviceRequestGenerator;
import com.android.identity.mdoc.response.DeviceResponseParser;
import com.android.identity.mdoc.response.DeviceResponseParser.DeviceResponse;
import com.android.identity.mdoc.response.DeviceResponseParser.Document;
import com.android.identity.util.Constants;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class DirectAccessTestUtils {

  private static PrivateKey getReaderCAPrivateKey()
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    // TODO: should get private key from KeysAndCertificates class instead of
    //  hard-coding it here.
    byte[] keyBytes = Base64.getDecoder()
        .decode(
            "ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDCI6BG/yRDzi307Rqq2Ndw5mYi2y4MR+n6IDqjl2Qw/Sdy8D5eCzp8mlcL/vCWnEq0=");
    EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance("EC");
    return kf.generatePrivate(spec);
  }

  private static X509Certificate getGoogleRootCa(Context context) throws CertificateException {
    InputStream certInputStream =
        context.getResources().openRawResource(com.android.identity.test.R.raw.google_reader_ca);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(certInputStream);
  }

  private static KeyPair generateEcdsaKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
    kpg.initialize(ecSpec);
    return kpg.generateKeyPair();
  }

  public static KeyPair generateReaderKeyPair() throws Exception {
    return generateEcdsaKeyPair();
  }

  private static KeyPair generateIssuingAuthorityKeyPair() throws Exception {
    return generateEcdsaKeyPair();
  }

  private static X509Certificate getSelfSignedIssuerAuthorityCertificate(
      KeyPair issuerAuthorityKeyPair)
      throws Exception {
    X500Name issuer = new X500Name("CN=State Of Utopia");
    X500Name subject = new X500Name("CN=State Of Utopia Issuing Authority Signing Key");

    // Valid from now to five years from now.
    Date now = new Date();
    final long kMilliSecsInOneYear = 365L * 24 * 60 * 60 * 1000;
    Date expirationDate = new Date(now.getTime() + 5 * kMilliSecsInOneYear);
    BigInteger serial = new BigInteger("42");
    JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serial, now,
        expirationDate, subject, issuerAuthorityKeyPair.getPublic());

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(
        issuerAuthorityKeyPair.getPrivate());
    byte[] encodedCert = builder.build(signer).getEncoded();

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream bais = new ByteArrayInputStream(encodedCert);
    X509Certificate result = (X509Certificate) cf.generateCertificate(bais);
    return result;
  }

  private static HashMap<String, FieldMdl> getDocumentData(Context context) {
    Bitmap bitmapPortrait = BitmapFactory.decodeResource(context.getResources(),
        com.android.identity.test.R.drawable.img_erika_portrait);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    bitmapPortrait.compress(Bitmap.CompressFormat.JPEG, 50, baos);
    byte[] portrait = baos.toByteArray();
    Bitmap bitmapSignature = BitmapFactory.decodeResource(context.getResources(),
        com.android.identity.test.R.drawable.img_erika_signature);
    baos.reset();
    bitmapSignature.compress(Bitmap.CompressFormat.JPEG, 50, baos);
    byte[] signature = baos.toByteArray();


    Bitmap biometric_template = Bitmap.createBitmap(200, 200, Bitmap.Config.ARGB_8888);
    baos.reset();
    biometric_template.compress(Bitmap.CompressFormat.JPEG, 50, baos);
    byte[] biometric = baos.toByteArray();

    HashMap<String, FieldMdl> fieldsMdl = new HashMap<String, FieldMdl>();
    fieldsMdl.put("given_name", new FieldMdl("given_name", FieldTypeMdl.STRING, "Erika"));
    fieldsMdl.put("family_name", new FieldMdl("family_name", FieldTypeMdl.STRING, "Mustermann"));
    fieldsMdl.put("birth_date", new FieldMdl("birth_date", FieldTypeMdl.STRING, "1971-09-01"));
    fieldsMdl.put("issue_date", new FieldMdl("issue_date", FieldTypeMdl.STRING, "2021-04-18"));
    fieldsMdl.put("expiry_date", new FieldMdl("expiry_date", FieldTypeMdl.STRING, "2026-04-18"));
    fieldsMdl.put("portrait", new FieldMdl("portrait", FieldTypeMdl.STRING, portrait));
    fieldsMdl.put("issuing_country", new FieldMdl("issuing_country", FieldTypeMdl.STRING, "US"));
    fieldsMdl.put("issuing_authority",
        new FieldMdl("issuing_authority", FieldTypeMdl.STRING, "Google"));
    fieldsMdl.put("document_number",
        new FieldMdl("document_number", FieldTypeMdl.STRING, "987654321"));
    fieldsMdl.put("signature_usual_mark",
        new FieldMdl("signature_usual_mark", FieldTypeMdl.BITMAP, signature));
    fieldsMdl.put("biometric_template_signature_sign",
        new FieldMdl("biometric_template_signature_sign", FieldTypeMdl.BITMAP, biometric));
    fieldsMdl.put("biometric_template_iris",
        new FieldMdl("biometric_template_iris", FieldTypeMdl.BITMAP, biometric));
    fieldsMdl.put("un_distinguishing_sign",
        new FieldMdl("un_distinguishing_sign", FieldTypeMdl.STRING, "US"));
    fieldsMdl.put("age_over_18", new FieldMdl("age_over_18", FieldTypeMdl.BOOLEAN, "true"));
    fieldsMdl.put("age_over_21", new FieldMdl("age_over_21", FieldTypeMdl.BOOLEAN, "true"));
    fieldsMdl.put("sex", new FieldMdl("sex", FieldTypeMdl.STRING, "2"));
    fieldsMdl.put("vehicle_category_code_1",
        new FieldMdl("vehicle_category_code_1", FieldTypeMdl.STRING, "A"));
    fieldsMdl.put("issue_date_1", new FieldMdl("issue_date_1", FieldTypeMdl.DATE, "2018-08-09"));
    fieldsMdl.put("expiry_date_1", new FieldMdl("expiry_date_1", FieldTypeMdl.DATE, "2024-10-20"));
    fieldsMdl.put("vehicle_category_code_2",
        new FieldMdl("vehicle_category_code_2", FieldTypeMdl.STRING, "B"));
    fieldsMdl.put("issue_date_2", new FieldMdl("issue_date_2", FieldTypeMdl.DATE, "2017-02-23"));
    fieldsMdl.put("expiry_date_2", new FieldMdl("expiry_date_2", FieldTypeMdl.DATE, "2024-10-20"));

    return fieldsMdl;

  }

  private static PersonalizationData getPersonalizationData(Context context,
      boolean requireUserAuthentication) {
    AccessControlProfileId idSelf = new AccessControlProfileId(0);
    AccessControlProfile.Builder profileSelfBuilder = new AccessControlProfile.Builder(
        idSelf).setUserAuthenticationRequired(requireUserAuthentication);
    if (requireUserAuthentication) {
      profileSelfBuilder.setUserAuthenticationTimeout(30 * 1000);
    }
    AccessControlProfile profileSelf = profileSelfBuilder.build();
    Collection<AccessControlProfileId> idsSelf = Arrays.asList(idSelf);

    HashMap<String, FieldMdl> hashMap = getDocumentData(context);

    UnicodeString birthDate = new UnicodeString(hashMap.get("birth_date").getValueString());
    birthDate.setTag(1004);
    UnicodeString issueDate = new UnicodeString(hashMap.get("issue_date").getValueString());
    issueDate.setTag(1004);
    UnicodeString expiryDate = new UnicodeString(hashMap.get("expiry_date").getValueString());
    expiryDate.setTag(1004);
    UnicodeString issueDateCatA = new UnicodeString(hashMap.get("issue_date_1").getValueString());
    issueDateCatA.setTag(1004);
    UnicodeString expiryDateCatA = new UnicodeString(hashMap.get("expiry_date_1").getValueString());
    expiryDateCatA.setTag(1004);
    UnicodeString issueDateCatB = new UnicodeString(hashMap.get("issue_date_2").getValueString());
    issueDateCatB.setTag(1004);
    UnicodeString expiryDateCatB = new UnicodeString(hashMap.get("expiry_date_2").getValueString());
    expiryDateCatB.setTag(1004);
    DataItem drivingPrivileges = new CborBuilder().addArray().addMap()
        .put("vehicle_category_code", hashMap.get("vehicle_category_code_1").getValueString())
        .put(new UnicodeString("issue_date"), issueDateCatA)
        .put(new UnicodeString("expiry_date"), expiryDateCatA).end().addMap()
        .put("vehicle_category_code", hashMap.get("vehicle_category_code_2").getValueString())
        .put(new UnicodeString("issue_date"), issueDateCatB)
        .put(new UnicodeString("expiry_date"), expiryDateCatB).end().end().build().get(0);
    PersonalizationData personalizationData = new PersonalizationData.Builder().putEntryString(
            CredentialDataParser.MDL_NAMESPACE, "given_name", idsSelf,
            hashMap.get("given_name").getValueString())
        .putEntryString(CredentialDataParser.MDL_NAMESPACE, "family_name", idsSelf,
            hashMap.get("family_name").getValueString())
        .putEntry(CredentialDataParser.MDL_NAMESPACE, "birth_date", idsSelf,
            Util.cborEncode((birthDate)))
        .putEntryBytestring(CredentialDataParser.MDL_NAMESPACE, "portrait", idsSelf,
            hashMap.get("portrait").getValueBitmapBytes())
        .putEntry(CredentialDataParser.MDL_NAMESPACE, "issue_date", idsSelf,
            Util.cborEncode(issueDate))
        .putEntry(CredentialDataParser.MDL_NAMESPACE, "expiry_date", idsSelf,
            Util.cborEncode(expiryDate))
        .putEntryString(CredentialDataParser.MDL_NAMESPACE, "issuing_country", idsSelf,
            hashMap.get("issuing_country").getValueString())
        .putEntryString(CredentialDataParser.MDL_NAMESPACE, "issuing_authority", idsSelf,
            hashMap.get("issuing_authority").getValueString())
        .putEntryString(CredentialDataParser.MDL_NAMESPACE, "document_number", idsSelf,
            hashMap.get("document_number").getValueString())
        .putEntry(CredentialDataParser.MDL_NAMESPACE, "driving_privileges", idsSelf,
            Util.cborEncode(drivingPrivileges))
        .putEntryString(CredentialDataParser.MDL_NAMESPACE, "un_distinguishing_sign", idsSelf,
            hashMap.get("un_distinguishing_sign").getValueString())
        .putEntryBoolean(CredentialDataParser.MDL_NAMESPACE, "age_over_18", idsSelf,
            hashMap.get("age_over_18").getValueBoolean())
        .putEntryBoolean(CredentialDataParser.MDL_NAMESPACE, "age_over_21", idsSelf,
            hashMap.get("age_over_21").getValueBoolean())
        .putEntryBytestring(CredentialDataParser.MDL_NAMESPACE, "signature_usual_mark", idsSelf,
            hashMap.get("signature_usual_mark").getValueBitmapBytes())
        .putEntryBytestring(CredentialDataParser.MDL_NAMESPACE, "biometric_template_iris", idsSelf,
            hashMap.get("biometric_template_iris").getValueBitmapBytes())
        .putEntryBytestring(CredentialDataParser.MDL_NAMESPACE, "biometric_template_signature_sign", idsSelf,
            hashMap.get("biometric_template_signature_sign").getValueBitmapBytes())
        .putEntryInteger(CredentialDataParser.MDL_NAMESPACE, "sex", idsSelf,
            Integer.valueOf(hashMap.get("sex").getValueString()))
        .addAccessControlProfile(profileSelf).build();
    return personalizationData;
  }


  public static byte[] createCredentialData(Context context,
      MDocCredential.MDocSigningKeyCertificationRequest authKeyCert,
      String docType, ArrayList<X509Certificate> readerPublicKeys) {
    try {
      KeyPair issuerKeypair = generateIssuingAuthorityKeyPair();
      return CredentialDataParser.generateCredentialData(
          docType,
          getPersonalizationData(context, false),
          authKeyCert.getCertificate().getPublicKey(),
          issuerKeypair,
          getSelfSignedIssuerAuthorityCertificate(issuerKeypair),
          readerPublicKeys);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create CredentialData error: " + e.getMessage());
    }
  }


  public static boolean validateMdocResponse(DeviceResponseParser.DeviceResponse response, String[] entries) {
    List<Document> documentList = response.getDocuments();
    for (Document doc : documentList) {
      for (String eleId : entries) {
        byte[] eleVal = doc.getIssuerEntryData(CredentialDataParser.MDL_NAMESPACE, eleId);
        if (eleVal == null) {
          return false;
        }
      }
    }
    return true;
  }

  public static byte[] createMdocRequest(@NonNull KeyPair readerKey,
      @NonNull ArrayList<X509Certificate> readerKeyCertChain, @NonNull String[] reqIds,
      @NonNull byte[] sessionTranscript) throws NoSuchAlgorithmException, InvalidKeyException {
    Map<String, Map<String, Boolean>> mdlNamespace = new HashMap<>();
    Map<String, Boolean> entries = new HashMap<>();
    for (String eleId : reqIds) {
      entries.put(eleId, false);
    }
    // entries.put("sex", false);
    // entries.put("portrait", false);
    // entries.put("given_name", false);
    // entries.put("issue_date", false);
    // entries.put("expiry_date", false);
    // entries.put("family_name", false);
    // entries.put("document_number", false);
    // entries.put("issuing_authority", false);
    mdlNamespace.put(CredentialDataParser.MDL_NAMESPACE, entries);
    Signature signature = null;
    if (readerKey != null) {
      signature = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
      signature.initSign(readerKey.getPrivate());
    }

    DeviceRequestGenerator generator = new DeviceRequestGenerator();
    generator.setSessionTranscript(sessionTranscript);
    generator.addDocumentRequest(CredentialDataParser.MDL_DOC_TYPE,
        mdlNamespace, null, signature, readerKeyCertChain);
    return generator.generate();
  }

  public static ArrayList<X509Certificate> getReaderCertificateChain(Context context,
      KeyPair readerKey, boolean isSelfSigned) throws Exception {
    ArrayList<X509Certificate> certChain = null;
    // TODO support for signing with Google root CA.
    X500Principal issuer = new X500Principal("CN=SelfSigned, O=Android, C=US");
    X500Principal subject = new X500Principal("CN=Subject, O=Android, C=US");
    // Make the certificate valid for two days.
    long millisPerDay = 24 * 60 * 60 * 1000;
    long now = System.currentTimeMillis();
    Date start = new Date(now - millisPerDay);
    Date end = new Date(now + millisPerDay);

    byte[] serialBytes = new byte[16];
    new SecureRandom().nextBytes(serialBytes);
    BigInteger serialNumber = new BigInteger(1, serialBytes);

    X509v3CertificateBuilder x509cg =
        new X509v3CertificateBuilder(
            X500Name.getInstance(issuer.getEncoded()),
            serialNumber,
            start,
            end,
            X500Name.getInstance(subject.getEncoded()),
            SubjectPublicKeyInfo.getInstance(readerKey.getPublic().getEncoded())
        );
    X509CertificateHolder x509holder =
        x509cg.build(
            new JcaContentSignerBuilder("SHA256withECDSA")
                .build(readerKey.getPrivate()));
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    X509Certificate x509c =
        (X509Certificate)
            certFactory.generateCertificate(
                new ByteArrayInputStream(x509holder.getEncoded()));
    certChain = new ArrayList<>();
    certChain.add(x509c);
    return certChain;
  }


}
