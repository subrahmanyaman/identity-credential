package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.icu.util.Calendar;
import android.se.omapi.SEService;
import android.se.omapi.SEService.OnConnectedListener;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import com.android.identity.android.legacy.AccessControlProfile;
import com.android.identity.android.legacy.AccessControlProfileId;
import com.android.identity.android.legacy.PersonalizationData;
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper;
import com.android.identity.android.mdoc.transport.DataTransportOptions;
import com.android.identity.android.storage.AndroidStorageEngine;
import com.android.identity.internal.Util;
import com.android.identity.mdoc.connectionmethod.ConnectionMethod;
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Timestamp;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class DirectAccessTestRef {

  private final long SERVICE_CONNECTION_TIME_OUT = 3000;
  private Object serviceMutex = new Object();
  private boolean connected = false;
  private Timer connectionTimer;
  private ServiceConnectionTimerTask mTimerTask = new ServiceConnectionTimerTask();
  private SEService mSEService;
  DirectAccessTransport mTransport;
  MDocStore mDocStore;
  String mDocName;
  StorageEngine mStorageEngine;
  Context mContext;
  public static String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";
  public static String MDL_NAMESPACE = "org.iso.18013.5.1";
  private final OnConnectedListener mListener = new OnConnectedListener() {
    public void onConnected() {
      synchronized (serviceMutex) {
        connected = true;
        serviceMutex.notify();
      }
    }
  };

  class SynchronousExecutor implements Executor {

    public void execute(Runnable r) {
      r.run();
    }
  }

  class ServiceConnectionTimerTask extends TimerTask {

    @Override
    public void run() {
      synchronized (serviceMutex) {
        serviceMutex.notifyAll();
      }
    }
  }

  private void waitForConnection() throws TimeoutException {
    if (mTransport instanceof DirectAccessSocketTransport) {
      return;
    }
    synchronized (serviceMutex) {
      if (!connected) {
        try {
          serviceMutex.wait();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      if (!connected) {
        throw new TimeoutException(
            "Service could not be connected after " + SERVICE_CONNECTION_TIME_OUT + " ms");
      }
      if (connectionTimer != null) {
        connectionTimer.cancel();
      }
    }
  }


  private DirectAccessTransport getDirectAccessTransport(boolean useSocketTransport) {
    if (useSocketTransport) {
      return new DirectAccessSocketTransport();
    } else {
      return new DirectAccessOmapiTransport(mSEService);
    }
  }


  @Before
  public void init() {
    mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
    mSEService = new SEService(mContext, new SynchronousExecutor(), mListener);
    File storageDir = new File(mContext.getDataDir(), "ic-testing");
    mStorageEngine = new AndroidStorageEngine.Builder(mContext, storageDir).build();
    connectionTimer = new Timer();
    connectionTimer.schedule(mTimerTask, SERVICE_CONNECTION_TIME_OUT);
    provision();
  }

  @After
  public void reset() {
    if (mDocStore != null) {
      mDocStore.deleteCredential(mDocName);
    }
    try {
      if (mTransport != null) {
        mTransport.closeConnection();
      }
    } catch (IOException e) {
      fail("Unexpected Exception " + e);
    }
  }

  private KeyPair generateIssuingAuthorityKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC);
    ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime256v1");
    kpg.initialize(ecSpec);
    return kpg.generateKeyPair();
  }

  private X509Certificate getSelfSignedIssuerAuthorityCertificate(KeyPair issuerAuthorityKeyPair)
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

  private HashMap<String, FieldMdl> getDocumentData() {
    Bitmap bitmapPortrait = BitmapFactory.decodeResource(mContext.getResources(),
        com.android.identity.test.R.drawable.img_erika_portrait);

    //val iaSelfSignedCert = KeysAndCertificates.getMdlDsCertificate(context)
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    bitmapPortrait.compress(Bitmap.CompressFormat.JPEG, 50, baos);
    byte[] portrait = baos.toByteArray();
    Bitmap bitmapSignature = BitmapFactory.decodeResource(mContext.getResources(),
        com.android.identity.test.R.drawable.img_erika_signature);
    baos.reset();
    bitmapSignature.compress(Bitmap.CompressFormat.JPEG, 50, baos);
    byte[] signature = baos.toByteArray();

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

  private byte[] cborEncode(DataItem dataItem) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try {
      new CborEncoder(baos).encode(dataItem);
    } catch (CborException e) {
      // This should never happen and we don't want cborEncode() to throw since that
      // would complicate all callers. Log it instead.
      throw new IllegalStateException("Unexpected failure encoding data", e);
    }
    return baos.toByteArray();
  }

  private PersonalizationData getPersonalizationData(boolean requireUserAuthentication) {
    AccessControlProfileId idSelf = new AccessControlProfileId(0);
    AccessControlProfile.Builder profileSelfBuilder = new AccessControlProfile.Builder(
        idSelf).setUserAuthenticationRequired(requireUserAuthentication);
    if (requireUserAuthentication) {
      profileSelfBuilder.setUserAuthenticationTimeout(30 * 1000);
    }
    AccessControlProfile profileSelf = profileSelfBuilder.build();
    Collection<AccessControlProfileId> idsSelf = Arrays.asList(idSelf);

    HashMap<String, FieldMdl> hashMap = getDocumentData();

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
            MDL_NAMESPACE, "given_name", idsSelf, hashMap.get("given_name").getValueString())
        .putEntryString(MDL_NAMESPACE, "family_name", idsSelf,
            hashMap.get("family_name").getValueString())
        .putEntry(MDL_NAMESPACE, "birth_date", idsSelf, cborEncode(birthDate))
        .putEntryBytestring(MDL_NAMESPACE, "portrait", idsSelf,
            hashMap.get("portrait").getValueBitmapBytes())
        .putEntry(MDL_NAMESPACE, "issue_date", idsSelf, cborEncode(issueDate))
        .putEntry(MDL_NAMESPACE, "expiry_date", idsSelf, cborEncode(expiryDate))
        .putEntryString(MDL_NAMESPACE, "issuing_country", idsSelf,
            hashMap.get("issuing_country").getValueString())
        .putEntryString(MDL_NAMESPACE, "issuing_authority", idsSelf,
            hashMap.get("issuing_authority").getValueString())
        .putEntryString(MDL_NAMESPACE, "document_number", idsSelf,
            hashMap.get("document_number").getValueString())
        .putEntry(MDL_NAMESPACE, "driving_privileges", idsSelf, cborEncode(drivingPrivileges))
        .putEntryString(MDL_NAMESPACE, "un_distinguishing_sign", idsSelf,
            hashMap.get("un_distinguishing_sign").getValueString())
        .putEntryBoolean(MDL_NAMESPACE, "age_over_18", idsSelf,
            hashMap.get("age_over_18").getValueBoolean())
        .putEntryBoolean(MDL_NAMESPACE, "age_over_21", idsSelf,
            hashMap.get("age_over_21").getValueBoolean())
        .putEntryBytestring(MDL_NAMESPACE, "signature_usual_mark", idsSelf,
            hashMap.get("signature_usual_mark").getValueBitmapBytes())
        .putEntryInteger(MDL_NAMESPACE, "sex", idsSelf,
            Integer.valueOf(hashMap.get("sex").getValueString()))
        .addAccessControlProfile(profileSelf).build();
    return personalizationData;
  }

  private byte[] createMobileSecurityObject(
      MDocCredential.MDocSigningKeyCertificationRequest authKeyCert,
      PersonalizationData personalizationData, HashMap<String, List<byte[]>> issuerSignedMapping) {
    final Timestamp signedDate = Timestamp.now();
    final Timestamp validFromDate = Timestamp.now();
    Calendar validToCalendar = Calendar.getInstance();
    validToCalendar.add(Calendar.MONTH, 12);
    final Timestamp validToDate = Timestamp.ofEpochMilli(validToCalendar.getTimeInMillis());
    PublicKey authKey = authKeyCert.getCertificate().getPublicKey();

    MobileSecurityObjectGenerator msoGenerator = new MobileSecurityObjectGenerator("SHA-256",
        MDL_DOCTYPE, authKey).setValidityInfo(signedDate, validFromDate, validToDate, null);

    Random r = new SecureRandom();

    // Count number of entries and generate digest ids
    int numEntries = 0;
    for (PersonalizationData.NamespaceData nsd : personalizationData.getNamespaceDatas()) {
      numEntries += nsd.getEntryNames().size();
    }
    List<Long> digestIds = new ArrayList<>();
    for (Long n = 0L; n < numEntries; n++) {
      digestIds.add(n);
    }
    Collections.shuffle(digestIds);

    //HashMap<String, List<byte[]>> issuerSignedMapping = new HashMap<>();

    Iterator<Long> digestIt = digestIds.iterator();
    for (PersonalizationData.NamespaceData nsd : personalizationData.getNamespaceDatas()) {
      String ns = nsd.getNamespaceName();

      List<byte[]> innerArray = new ArrayList<>();

      Map<Long, byte[]> vdInner = new HashMap<>();

      for (String entry : nsd.getEntryNames()) {
        byte[] encodedValue = nsd.getEntryValue(entry);
        Long digestId = digestIt.next();
        byte[] random = new byte[16];
        r.nextBytes(random);
        DataItem value = Util.cborDecode(encodedValue);

        DataItem issuerSignedItem = new CborBuilder().addMap().put("digestID", digestId)
            .put("random", random).put("elementIdentifier", entry)
            .put(new UnicodeString("elementValue"), value).end().build().get(0);
        byte[] encodedIssuerSignedItem = Util.cborEncode(issuerSignedItem);

        byte[] digest = null;
        byte[] encodedIssuerSignedItemBytes = null;
        try {
          // For the digest, it's of the _tagged_ bstr so wrap it
          encodedIssuerSignedItemBytes = Util.cborEncode(
              Util.cborBuildTaggedByteString(encodedIssuerSignedItem));
          //print(encodedIssuerSignedItemBytes);
          digest = MessageDigest.getInstance("SHA-256").digest(encodedIssuerSignedItemBytes);
        } catch (NoSuchAlgorithmException e) {
          throw new IllegalArgumentException("Failed creating digester", e);
        }

        // Replace elementValue in encodedIssuerSignedItem with NULL value.
        //
        // byte[] encodedIssuerSignedItemCleared = Util.issuerSignedItemClearValue(
        //     encodedIssuerSignedItem);
        innerArray.add(encodedIssuerSignedItemBytes);

        vdInner.put(digestId, digest);
      }

      issuerSignedMapping.put(ns, innerArray);

      msoGenerator.addDigestIdsForNamespace(ns, vdInner);
    }

    byte[] encodedMobileSecurityObject = msoGenerator.generate();

    byte[] taggedEncodedMso = Util.cborEncode(
        Util.cborBuildTaggedByteString(encodedMobileSecurityObject));
    KeyPair issuerAuthorityKeyPair = null;
    X509Certificate issuerAuthorityCertificate = null;
    try {
      issuerAuthorityKeyPair = generateIssuingAuthorityKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to generate issuing Authority key " + e);
    }
    try {
      issuerAuthorityCertificate = getSelfSignedIssuerAuthorityCertificate(issuerAuthorityKeyPair);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to generate self signed cert for IA " + e);
    }

    // IssuerAuth is a COSE_Sign1 where payload is MobileSecurityObjectBytes
    //
    // MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
    //
    ArrayList<X509Certificate> issuerAuthorityCertChain = new ArrayList<>();
    issuerAuthorityCertChain.add(issuerAuthorityCertificate);
    byte[] encodedIssuerAuth = Util.cborEncode(
        Util.coseSign1Sign(issuerAuthorityKeyPair.getPrivate(), "SHA256withECDSA", taggedEncodedMso,
            null, issuerAuthorityCertChain));

    return encodedIssuerAuth;
  }

  private byte[] createCredentialData(MDocCredential.MDocSigningKeyCertificationRequest authKeyCert,
      String docType) {
    //   CredentialData = {
    //     "docType": tstr,
    //     "issuerNameSpaces": IssuerNameSpaces,
    //     "issuerAuth" : IssuerAuth,
    //     "readerAccess" : ReaderAccess
    //   }
    //
    //   IssuerNameSpaces = {
    //     NameSpace => [ + IssuerSignedItemBytes ]
    //   }
    //
    //   ReaderAccess = [ * COSE_Key ]
    PersonalizationData personalizationData = getPersonalizationData(false);
    HashMap<String, List<byte[]>> issuerSignedMapping = new HashMap<>();
    byte[] encodedIssuerAuth = createMobileSecurityObject(authKeyCert, personalizationData,
        issuerSignedMapping);

    CborBuilder digestIdBuilder = new CborBuilder();
    MapBuilder<CborBuilder> outerBuilder = digestIdBuilder.addMap();
    for (String namespace : issuerSignedMapping.keySet()) {
      ArrayBuilder<MapBuilder<CborBuilder>> innerBuilder = outerBuilder.putArray(namespace);

      for (byte[] encodedIssuerSignedItemMetadata : issuerSignedMapping.get(namespace)) {
        innerBuilder.add(Util.cborDecode(encodedIssuerSignedItemMetadata));
      }
    }
    DataItem digestIdMappingItem = digestIdBuilder.build().get(0);
    // build reader access

    byte[] credentialData = Util.cborEncode(
        new CborBuilder().addMap().put(new UnicodeString("docType"), new UnicodeString(docType))
            .put(new UnicodeString("issuerNameSpaces"), digestIdMappingItem)
            .put(new UnicodeString("issuerAuth"), Util.cborDecode(encodedIssuerAuth))
            .put(new UnicodeString("readerAccess"), new Array()) // Empty reader access.
            .end().build().get(0));

    return credentialData;
  }

  private VerificationHelper.Listener mResponseListener = new VerificationHelper.Listener() {


    @Override
    public void onReaderEngagementReady(@NonNull byte[] readerEngagement) {

    }

    @Override
    public void onDeviceEngagementReceived(@NonNull List<ConnectionMethod> connectionMethods) {

    }

    @Override
    public void onMoveIntoNfcField() {

    }

    @Override
    public void onDeviceConnected() {

    }

    @Override
    public void onDeviceDisconnected(boolean transportSpecificTermination) {

    }

    @Override
    public void onResponseReceived(@NonNull byte[] deviceResponseBytes) {

    }

    @Override
    public void onError(@NonNull Throwable error) {

    }
  };

  private void provision() {
    mDocName = "mDL";
    mTransport = getDirectAccessTransport(true);
    try {
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      mDocStore = new MDocStore(mTransport, mStorageEngine);
      MDocCredential credential = mDocStore.createCredential(mDocName, MDL_DOCTYPE, challenge,
          numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
      List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
          Duration.ofDays(180));
      Assert.assertEquals(numSigningKeys, certificationRequests.size());
      // Provision
      byte[] encodedCredData = createCredentialData(certificationRequests.get(0), MDL_DOCTYPE);
      print(encodedCredData);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  public void doPresentation() {
    VerificationHelper.Builder builder = new VerificationHelper.Builder(mContext,
        mResponseListener, mContext.getMainExecutor());
    DataTransportOptions options = new DataTransportOptions.Builder()
        .setBleClearCache(false)
        .setBleClearCache(false)
            .build();
    builder.setDataTransportOptions(options);
  }

  @Test
  public void testCreateCredential() {
    provision();
    // MDocStore mDocStore = null;
    // String mDocName = "mDL";
    // DirectAccessTransport transport = getDirectAccessTransport(true);
    // try {
    //   //waitForConnection();
    //   byte[] challenge = "challenge".getBytes();
    //   int numSigningKeys = 2;
    //   mDocStore = new MDocStore(transport, mStorageEngine);
    //   MDocCredential credential = mDocStore.createCredential(mDocName, MDL_DOCTYPE, challenge,
    //       numSigningKeys, Duration.ofDays(365));
    //   List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
    //   Assert.assertTrue(certificates.size() >= 1);
    //   Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    //   List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
    //       Duration.ofDays(180));
    //   Assert.assertEquals(numSigningKeys, certificationRequests.size());
    //   // Provision
    //   byte[] encodedCredData = createCredentialData(certificationRequests.get(0), MDL_DOCTYPE);
    //   print(encodedCredData);
    //   credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
    //
    //   // Presentation
    //
    // } catch (Exception e) {
    //   fail("Unexpected Exception " + e);
    // } finally {
    //   if (mDocStore != null) {
    //     mDocStore.deleteCredential(mDocName);
    //   }
    //   try {
    //     if (transport != null) {
    //       transport.closeConnection();
    //     }
    //   } catch (IOException e) {
    //     fail("Unexpected Exception " + e);
    //   }
    // }
  }
  @Test
  public void createCredentialWithInvalidDocType() {

  }

  @Test
  public void provisionInvalidCredentialData() {

  }

  @Test
  public void createCredentialWithLargeChallenge() {
  }

  public static void print(byte[] data) {
    int NO_CHARS_IN_LINE = 250;
    int noCounts = data.length / NO_CHARS_IN_LINE;
    int remaining = data.length % NO_CHARS_IN_LINE;
    int i = 0;
    for (; i < noCounts; i++) {
      String str = tohexStr(data, (NO_CHARS_IN_LINE * i), NO_CHARS_IN_LINE);
      Log.d("<======>[" + i + "]", str);
    }
    String str = tohexStr(data, (i * NO_CHARS_IN_LINE), remaining);
    Log.d("<======>[" + i + "]", str);
  }

  public static String tohexStr(byte[] data, int off, int len) {
    StringBuilder sb = new StringBuilder();
    System.out.println("----");
    for (int i = off; i < (off + len); i++) {
      sb.append(String.format("%02X", data[i]));
    }
    return sb.toString();
  }

}
