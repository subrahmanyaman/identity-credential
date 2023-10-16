package com.android.identity.android.direct_access;

import androidx.annotation.NonNull;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.android.identity.internal.Util;
import com.android.identity.storage.StorageEngine;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class MDocCredential {

  private static final String TAG = "MDocCredential";
  private static final String MDOC_CREDENTIAL_PREFIX = "DA_Credential_";
  private static final String MDOC_PREFIX = "DA_AndroidKeystore_";
  private static final long CREDENTIAL_KEY_VALID_DURATION = (365 * 24 * 60 * 60 * 1000);
  private static final byte PROVISION_BEGIN = 0;
  private static final byte PROVISION_UPDATE = 1;
  private static final byte PROVISION_FINISH = 2;
  private static final int SLOT_0 = 0;
  private final StorageEngine mStorageEngine;
  private final DirectAccessTransport mTransport;
  private int mNumSigningKeys;
  private Duration mSigningKeyMinValidDuration;
  private String mDocName;
  private String mDocType;
  private int mSlot;
  DirectAccessCborHelper mCborHelper;
  DirectAccessAPDUHelper mApduHelper;

  private MDocCredential(@NonNull StorageEngine storageEngine,
      @NonNull DirectAccessTransport mTransport) {
    this.mStorageEngine = storageEngine;
    this.mTransport = mTransport;
  }

  public static MDocCredential create(@NonNull String name, @NonNull String docType,
      @NonNull byte[] challenge, int numSigningKeys, @NonNull Duration signingKeyMinValidDuration,
      @NonNull StorageEngine storageEngine, @NonNull DirectAccessTransport transport) {
    MDocCredential credential = new MDocCredential(storageEngine, transport);
    credential.mNumSigningKeys = numSigningKeys;
    credential.mDocName = name;
    credential.mDocType = docType;
    credential.mSigningKeyMinValidDuration = signingKeyMinValidDuration;
    credential.mApduHelper = new DirectAccessAPDUHelper();
    credential.mCborHelper = new DirectAccessCborHelper();
    credential.mSlot = credential.getNextAvailableSlot();
    // TODO Remove below dummy code.
    long notBefore = System.currentTimeMillis();
    long notAfter = notBefore + CREDENTIAL_KEY_VALID_DURATION;
    // Create credential key
    byte[] apdu = null;
    byte[] response = null;
    try {
      apdu = credential.mApduHelper.createCredentialAPDU(credential.mSlot, challenge, notBefore, notAfter);
      response = credential.mTransport.sendData(apdu);
      print(response, (short) 0, (short) response.length);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to send createCredential APDU command");
    }
    List<X509Certificate> credentialKeyCert = credential.mCborHelper.decodeCredentialKeyResponse(response);

    List<PresentationPackage> presentationPackages = credential.createPresentationPackage(
        credential.mSlot);
    credential.saveCredentialKeyCert(name, docType, numSigningKeys,
        credentialKeyCert);
    credential.savePresentationPackage(presentationPackages);
    return credential;
  }

  private int getNextAvailableSlot() {
    // Currently Applet supports only one slot.
    return SLOT_0;
  }

  private List<PresentationPackage> createPresentationPackage(int slot) {
    byte[] response = null;
    List<PresentationPackage> presentationPackages = new ArrayList<>();
    try {
      for (int i = 0; i < mNumSigningKeys; i++) {
        byte[] apdu = mApduHelper.createPresentationPackageAPDU(slot, mSigningKeyMinValidDuration);
        response = mTransport.sendData(apdu);
        // Decode presentation package.
        presentationPackages.add(mCborHelper.decodePresentationPackage(response));
        print(response, (short) 0, (short) response.length);
      }
    } catch (IOException e) {
      throw new IllegalStateException("Failed to create presentation package", e);
    }
    return presentationPackages;
  }

  public static MDocCredential lookupCredential(@NonNull String name,
      @NonNull StorageEngine storageEngine, @NonNull DirectAccessTransport transport) {
    MDocCredential credential = new MDocCredential(storageEngine, transport);
    credential.mDocName = name;
    Map map = credential.parseSavedCredential();
    DataItem numSigningKeysDataItem = map.get(new UnicodeString("numSigningKeys"));
    if (numSigningKeysDataItem != null) {
      credential.mNumSigningKeys = ((UnsignedInteger)numSigningKeysDataItem).getValue().intValue();
    }
    DataItem docTypeItem = map.get(new UnicodeString("docType"));
    if (docTypeItem != null) {
      credential.mDocType = ((UnicodeString)docTypeItem).getString();
    }
    DataItem minValidDurationItem = map.get(new UnicodeString("signingKeyMinValidDuration"));
    if (minValidDurationItem != null) {
      long milliseconds = ((UnsignedInteger)numSigningKeysDataItem).getValue().longValue();
      credential.mSigningKeyMinValidDuration = Duration.ofMillis(milliseconds);
    }
    credential.mApduHelper = new DirectAccessAPDUHelper();
    credential.mCborHelper = new DirectAccessCborHelper();
    credential.mSlot = credential.getNextAvailableSlot();
    return credential;
  }

  private boolean isSigningKeyCertReqeustProvisioned(MDocSigningKeyCertificationRequest request) {
    co.nstant.in.cbor.model.Map map = parsePresentationPackage();
    DataItem ppItem = map.get(new UnicodeString("presentationPackage"));
    co.nstant.in.cbor.model.Array ppArray = (co.nstant.in.cbor.model.Array) ppItem;
    List<DataItem> mapItems = ppArray.getDataItems();
    for (DataItem item : mapItems) {
      X509Certificate cert = getSigningKeyCert(item);
      if (request.getCertificate().equals(cert)) {
        return ((Map) item).get(new UnicodeString("provisionedSlot")) != null;
      }
    }
    return false;
  }

  private void saveEncryptedDataPresentationPackage(MDocSigningKeyCertificationRequest request,
      byte[] encryptedData, Instant expirationDate) {
    co.nstant.in.cbor.model.Map map = parsePresentationPackage();
    DataItem ppItem = map.get(new UnicodeString("presentationPackage"));
    co.nstant.in.cbor.model.Array ppArray = (co.nstant.in.cbor.model.Array) ppItem;
    List<DataItem> mapItems = ppArray.getDataItems();
    for (DataItem item : mapItems) {
      X509Certificate cert = getSigningKeyCert(item);
      if (request.getCertificate().equals(cert)) {
        ((Map) item).remove(new UnicodeString("encryptedData"));
        ((Map) item).put(new UnicodeString("encryptedData"), new ByteString(encryptedData));
        ((Map) item).put(new UnicodeString("expirationDate"),
            new UnsignedInteger(expirationDate.getEpochSecond()));
        ((Map) item).put(new UnicodeString("provisionedSlot"),
            new UnsignedInteger(SLOT_0));
        break;
      }
    }
    mStorageEngine.delete(MDOC_PREFIX + mDocName);
    mStorageEngine.put(MDOC_PREFIX + mDocName,
        Util.cborEncode(map));
  }

  private void savePresentationPackage( @NonNull List<PresentationPackage> presentationPackages) {
    CborBuilder builder = new CborBuilder();
    MapBuilder<CborBuilder> map = builder.addMap();
    ArrayBuilder<MapBuilder<CborBuilder>> authKeysBuilder = map.putArray("presentationPackage");
    for (PresentationPackage presentationPackage : presentationPackages) {
      MapBuilder<ArrayBuilder<MapBuilder<CborBuilder>>> presentationPackageMap = authKeysBuilder.addMap();
      presentationPackageMap.put("usageCount", 0);
      ArrayBuilder<MapBuilder<ArrayBuilder<MapBuilder<CborBuilder>>>> signCertBuilder = presentationPackageMap.putArray(
          "authenticationKeys");
      for (X509Certificate certificate : presentationPackage.signingCert) {
        try {
          signCertBuilder.add(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
          throw new IllegalStateException("Error encoding certificate chain", e);
        }
      }
      signCertBuilder.end();
      presentationPackageMap.put("encryptedData", presentationPackage.encryptedData);
      presentationPackageMap.end();
    }
    authKeysBuilder.end();
    mStorageEngine.put(MDOC_PREFIX + mDocName,
        Util.cborEncode(builder.build().get(0)));
  }

  private void saveCredentialKeyCert(@NonNull String name, @NonNull String docType,
      int numSigningKeys,
      List<X509Certificate> credCert) {
    CborBuilder builder = new CborBuilder();
    MapBuilder<CborBuilder> map = builder.addMap();
    map.put("docType", mDocType);
    map.put("signingKeyMinValidDuration", mSigningKeyMinValidDuration.toMillis());
    map.put("numSigningKeys", numSigningKeys);
    ArrayBuilder<MapBuilder<CborBuilder>> attestationBuilder = map.putArray("attestation");
    for (X509Certificate certificate : credCert) {
      try {
        attestationBuilder.add(certificate.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new IllegalStateException("Error encoding certificate chain", e);
      }
    }
    attestationBuilder.end();
    mStorageEngine.put(MDOC_CREDENTIAL_PREFIX + mDocName,
        Util.cborEncode(builder.build().get(0)));
  }

  private co.nstant.in.cbor.model.Map parseStoredData(String path) {
    byte[] data = mStorageEngine.get(path);
    ByteArrayInputStream bais = new ByteArrayInputStream(data);
    List<DataItem> dataItems;
    try {
      dataItems = new CborDecoder(bais).decode();
    } catch (CborException e) {
      throw new IllegalStateException("Error decoded CBOR", e);
    }
    if (dataItems.size() != 1) {
      throw new IllegalStateException("Expected 1 item, found " + dataItems.size());
    }
    if (!(dataItems.get(0) instanceof co.nstant.in.cbor.model.Map)) {
      throw new IllegalStateException("Item is not a map");
    }

    return (co.nstant.in.cbor.model.Map) dataItems.get(0);
  }

  private co.nstant.in.cbor.model.Map parseSavedCredential() {
    return parseStoredData(MDOC_CREDENTIAL_PREFIX + mDocName);
  }

  private co.nstant.in.cbor.model.Map parsePresentationPackage() {
    return parseStoredData(MDOC_PREFIX + mDocName);
  }

  // Gets the certificate chain and attestation for CredentialKey. The
  // `challenge` parameter passed to createCredential() is included
  // in the Android attestation extension. CredentialKey is not a KeyMint
  // key but it uses the same style of attestation.
  //
  public List<X509Certificate> getCredentialKeyCertificateChain() {
    co.nstant.in.cbor.model.Map map = parseSavedCredential();
    DataItem attestationDataItem = map.get(new UnicodeString("attestation"));
    if (!(attestationDataItem instanceof Array)) {
      throw new IllegalStateException("attestation not found or not array");
    }
    List<X509Certificate> attestation = new ArrayList<>();
    for (DataItem item : ((Array) attestationDataItem).getDataItems()) {
      byte[] encodedCert = ((ByteString) item).getBytes();
      try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
        attestation.add((X509Certificate) cf.generateCertificate(certBais));
      } catch (CertificateException e) {
        throw new IllegalStateException("Error decoding certificate blob", e);
      }
    }
    return attestation;
  }

  // Gets the number of signing keys for the credential, this is the same
  // same as the `numSigningKeys` parameter passed to createMDocCredential().
  //
  public int getNumSigningKeys() {
    co.nstant.in.cbor.model.Map map = parseSavedCredential();
    DataItem numSigningKeysDataItem = map.get(new UnicodeString("numSigningKeys"));
    if (!(numSigningKeysDataItem instanceof co.nstant.in.cbor.model.Number)) {
      throw new IllegalStateException("numSigningKeys not found or not Number");
    }
    return ((co.nstant.in.cbor.model.Number) numSigningKeysDataItem).getValue().intValue();
  }

  // Gets the duration a signing key must still be valid for until a
  // replacement will be requested. This is the same as the parameter
  // `signingKeyMinValidDuration` passed to createMDocCredential().
  //
  public Duration getSigningKeyMinValidDuration() {
    co.nstant.in.cbor.model.Map map = parseSavedCredential();
    DataItem signingKeyMinValidDuration = map.get(new UnicodeString("signingKeyMinValidDuration"));
    if (!(signingKeyMinValidDuration instanceof co.nstant.in.cbor.model.Number)) {
      throw new IllegalStateException("signingKeyMinValidDuration not found or not Number");
    }
    long duration = ((co.nstant.in.cbor.model.Number) signingKeyMinValidDuration).getValue()
        .longValue();
    return Duration.ofMillis(duration);
  }

  // Returns information about signing keys for the credential.
  //
  // The returned list is always `numSigningKeys` elements long but may
  // contains nulls if the signing key hasn't been provisioned yet.
  //
  public List<MDocSigningKeyMetadata> getSigningKeysMetadata() {
    co.nstant.in.cbor.model.Map map = parseSavedCredential();
    DataItem ppItem = map.get(new UnicodeString("presentationPackage"));
    co.nstant.in.cbor.model.Array ppArray = (co.nstant.in.cbor.model.Array) ppItem;
    List<DataItem> mapItems = ppArray.getDataItems();
    List<MDocSigningKeyMetadata> metadataList = new ArrayList<>();
    for (DataItem item : mapItems) {
      MDocSigningKeyMetadata metadata = new MDocSigningKeyMetadata();
      co.nstant.in.cbor.model.Map mapEntry = (co.nstant.in.cbor.model.Map) item;
      DataItem usageCountItem = mapEntry.get(new UnicodeString("usageCount"));
      int usageCount = ((UnsignedInteger) usageCountItem).getValue().intValue();
      DataItem expiryDateItem = mapEntry.get(new UnicodeString("ExpiryDate"));
      metadata.mUsageCount = usageCount;
      metadata.mExpirationDate = null;
      if (expiryDateItem != null) {
        long expiryDate = ((UnsignedInteger) usageCountItem).getValue().longValue();
        metadata.mExpirationDate = Instant.ofEpochMilli(expiryDate);
      }
      metadataList.add(metadata);
    }
    return metadataList;
  }

  // Clears all signing keys and associated data.
  //
  // This should be used when PII in a credential is updated.
  //
  public void clearAllSigningKeys() {
    mStorageEngine.delete(MDOC_PREFIX + mDocName + "_" + mDocType);
  }

  private byte[] getEncryptedDataPresentationPackage(MDocSigningKeyCertificationRequest request) {
    co.nstant.in.cbor.model.Map map = parsePresentationPackage();
    DataItem ppItem = map.get(new UnicodeString("presentationPackage"));
    co.nstant.in.cbor.model.Array ppArray = (co.nstant.in.cbor.model.Array) ppItem;
    List<DataItem> mapItems = ppArray.getDataItems();
    for (DataItem item : mapItems) {
      X509Certificate cert = getSigningKeyCert(item);
      if (request.getCertificate().equals(cert)) {
        DataItem encryptedDataItem = ((Map) item).get(new UnicodeString("encryptedData"));
        return ((ByteString) encryptedDataItem).getBytes();
      }
    }
    return null;
  }

  private X509Certificate getSigningKeyCert(DataItem presentationPackageItem) {
    co.nstant.in.cbor.model.Map mapEntry = (co.nstant.in.cbor.model.Map) presentationPackageItem;
    DataItem authenticationKeys = mapEntry.get(new UnicodeString("authenticationKeys"));
    List<DataItem> dataItems = ((Array) authenticationKeys).getDataItems();
    DataItem leafCertItem = dataItems.get(0); // Leaf
    byte[] certData = ((ByteString) leafCertItem).getBytes();
    X509Certificate cert = null;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(certData);
      cert = ((X509Certificate) cf.generateCertificate(bis));
    } catch (CertificateException e) {
      throw new IllegalStateException("Error generating certificate from response", e);
    }
    return cert;
  }

  // Gets all pending requests to have signing keys certified.
  //
  // This includes replacement signing keys for keys that are still valid but
  // are about to expire soon that is, inside the window returned by
  // getSigningKeyMinValidTimeMillis().
  //
  public List<MDocSigningKeyCertificationRequest> getSigningKeyCertificationRequests(
      Duration validityPeriod) {
    co.nstant.in.cbor.model.Map map = parsePresentationPackage();
    DataItem ppItem = map.get(new UnicodeString("presentationPackage"));
    co.nstant.in.cbor.model.Array ppArray = (co.nstant.in.cbor.model.Array) ppItem;
    List<DataItem> mapItems = ppArray.getDataItems();
    List<MDocSigningKeyCertificationRequest> certificationRequests = new ArrayList<>();
    for (DataItem item : mapItems) {
      MDocSigningKeyCertificationRequest certificationRequest =
          new MDocSigningKeyCertificationRequest();
      X509Certificate cert = getSigningKeyCert(item);
      try {
        cert.checkValidity(Date.from(Instant.now().plus(validityPeriod)));
      } catch (CertificateExpiredException | CertificateNotYetValidException e) {
        continue;
      }
      certificationRequest.mSigningCertificate = cert;
      certificationRequests.add(certificationRequest);
    }
    return certificationRequests;
  }

  private byte[] provision(int slot, byte[] data, int offset, int length, byte operation) throws IOException {
    byte[] beginApdu = mApduHelper.createProvisionApdu(slot,
        data, 0, length, operation);
    byte[] response = mTransport.sendData(beginApdu);
    return mCborHelper.decodeProvisionResponse(response);
  }

  // Provisions credential data for a specific signing key request.
  //
  // The |credentialData| parameter must be CBOR conforming to the following CDDL:
  //
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
  //
  // This data will stored on the Secure Area and used for MDOC presentations
  // using NFC data transfer in low-power mode.
  //
  // The `readerAccess` field contains a list of keys used for implementing
  // reader authentication. If this list is non-empty, reader authentication
  // is not required. Otherwise the request must be be signed and the request is
  // authenticated if, and only if, a public keys from the X.509 certificate
  // chain for the key signing the request exists in the `readerAccess` list.
  //
  // If reader authentication fails, the returned DeviceResponse shall return
  // error code 10 for the requested docType in the "documentErrors" field.
  //
  public void provision(MDocSigningKeyCertificationRequest request, Instant expirationDate,
      byte[] credentialData) {
    ByteArrayOutputStream bao = new ByteArrayOutputStream();
    try {
      // BEGIN
      byte[] encryptedData = getEncryptedDataPresentationPackage(request);
      bao.write(provision(SLOT_0,
          encryptedData, 0, encryptedData.length, PROVISION_BEGIN));

      // UPDATE
      int remaining = credentialData.length;
      int start = 0;
      int maxTransmitBufSize = 512;
      while(remaining > maxTransmitBufSize) {
        bao.write(provision(SLOT_0,
            credentialData, start, maxTransmitBufSize, PROVISION_UPDATE));
        start += maxTransmitBufSize;
        remaining -= maxTransmitBufSize;
      }

      // Finish
      bao.write(provision(SLOT_0,
          credentialData, start, remaining, PROVISION_FINISH));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to provision credential data "+e);
    }
    saveEncryptedDataPresentationPackage(request, bao.toByteArray(), expirationDate);
  }

  public static class MDocSigningKeyCertificationRequest {
    private X509Certificate mSigningCertificate;

    static MDocSigningKeyCertificationRequest create(X509Certificate signingCertificate) {
      MDocSigningKeyCertificationRequest certificationRequest = new MDocSigningKeyCertificationRequest();
      certificationRequest.mSigningCertificate = signingCertificate;
      return certificationRequest;
    }

    public X509Certificate getCertificate() {
      return mSigningCertificate;
    }
  }

  public static class MDocSigningKeyMetadata {

    private int mUsageCount;
    private Instant mExpirationDate;

    static MDocSigningKeyMetadata create(int usageCount, Instant expirationDate) {
      MDocSigningKeyMetadata metadata = new MDocSigningKeyMetadata();
      metadata.mUsageCount = usageCount;
      metadata.mExpirationDate = expirationDate;
      return metadata;
    }

    // Returns how many times the signing key has been used.
    //
    public int getUsageCount() {
      return mUsageCount;
    }

    // Returns the expiration date which was passed to the provision() call
    // when the signing key was certified.
    //
    public Instant getExpirationDate() {
      return mExpirationDate;
    }


  }

  void deleteCredential() {
    try {
      byte[] apdu = mApduHelper.deleteMDocAPDU(mSlot);
      byte[] response = mTransport.sendData(apdu);
      mCborHelper.decodeDeleteCredential(response);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to delete MDoc");
    }
    mStorageEngine.delete( MDOC_CREDENTIAL_PREFIX + mDocName + "_" + mDocType);
    mStorageEngine.delete( MDOC_PREFIX + mDocName + "_" + mDocType);
  }

  public static void print(byte[] buf, short start, short length) {
    StringBuilder sb = new StringBuilder();
    System.out.println("----");
    for (int i = start; i < (start + length); i++) {
      sb.append(String.format("%02X", buf[i]));
    }
    System.out.println(sb);
  }
}
