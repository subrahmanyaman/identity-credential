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

import android.icu.util.Calendar;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import com.android.identity.android.legacy.PersonalizationData;
import com.android.identity.internal.Util;
import com.android.identity.mdoc.mso.MobileSecurityObjectGenerator;
import com.android.identity.mdoc.mso.MobileSecurityObjectParser;
import com.android.identity.util.Logger;
import com.android.identity.util.Timestamp;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public class CredentialDataParser {

  public static final String MDL_DOC_TYPE = "org.iso.18013.5.1.mDL";
  public static final String MDL_NAMESPACE = "org.iso.18013.5.1";
  public static final String CRED_DATA_KEY_DOC_TYPE = "docType";
  public static final String CRED_DATA_KEY_ISSUER_NAMESPACES = "issuerNameSpaces";
  public static final String CRED_DATA_KEY_ISSUER_AUTH = "issuerAuth";

  public static final String ISSUER_SIGNED_ITEM_KEY_DIGEST_ID = "digestID";
  public static final String ISSUER_SIGNED_ITEM_KEY_RANDOM = "random";
  public static final String ISSUER_SIGNED_ITEM_KEY_ELE_ID = "elementIdentifier";
  public static final String ISSUER_SIGNED_ITEM_KEY_ELE_VAL = "elementValue";


  public static byte[] generateCredentialData(String docType, PersonalizationData personalizationData,
      PublicKey authKey, KeyPair issuerAuthorityKeyPair,
      X509Certificate issuerAuthorityCertificate, ArrayList<X509Certificate> readerCerts) {
    HashMap<String, List<byte[]>> issuerSignedMapping = generateIssuerNamespaces(
        personalizationData);
    byte[] encodedIssuerAuth = createMobileSecurityObject(docType, authKey, personalizationData,
        issuerSignedMapping, issuerAuthorityKeyPair, issuerAuthorityCertificate);

    CborBuilder issuerNamespacesBuilder = new CborBuilder();
    MapBuilder<CborBuilder> outerBuilder = issuerNamespacesBuilder.addMap();
    for (String namespace : issuerSignedMapping.keySet()) {
      ArrayBuilder<MapBuilder<CborBuilder>> innerBuilder = outerBuilder.putArray(namespace);

      for (byte[] encodedIssuerSignedItemMetadata : issuerSignedMapping.get(namespace)) {
        innerBuilder.add(Util.cborDecode(encodedIssuerSignedItemMetadata));
      }
    }
    DataItem issuerNamespacesItem = issuerNamespacesBuilder.build().get(0);
    // reader keys
    ArrayBuilder<CborBuilder> readerBuilder = new CborBuilder().addArray();
    if (readerCerts != null) {
      for (X509Certificate cert : readerCerts) {
        byte[] pubKey = getAndFormatRawPublicKey(cert);
        readerBuilder.add(pubKey);
      }
    }
    DataItem readerAuth = readerBuilder.end().build().get(0);
    return Util.cborEncode(
        new CborBuilder().addMap().put(new UnicodeString("docType"), new UnicodeString(docType))
            .put(new UnicodeString("issuerNameSpaces"), issuerNamespacesItem)
            .put(new UnicodeString("issuerAuth"), Util.cborDecode(encodedIssuerAuth))
            .put(new UnicodeString("readerAccess"), readerAuth)
            .end().build().get(0));
  }

  public static void validateCredentialData(byte[] encodedCredentialData) {
    DataItem credentialDataItem = Util.cborDecode(encodedCredentialData);
    if (Util.cborMapExtractMapStringKeys(credentialDataItem).size() != 4) {
      throw new IllegalArgumentException("CredentialData must have a size of 4");
    }
    String docType = Util.cborMapExtractString(credentialDataItem, CRED_DATA_KEY_DOC_TYPE);
    if (docType.compareTo(MDL_DOC_TYPE) != 0) {
      throw new IllegalArgumentException(
          "Given docType '" + docType + "' != '" + MDL_DOC_TYPE + "'");
    }
    if (!Util.cborMapHasKey(credentialDataItem, CRED_DATA_KEY_ISSUER_NAMESPACES)) {
      throw new IllegalArgumentException("Missing 'issuerNamespaces' in CredentialDat");
    }
    HashMap<String, List<byte[]>> issuerNamespaces = getIssuerNamespaces(credentialDataItem);
    if (!Util.cborMapHasKey(credentialDataItem, CRED_DATA_KEY_ISSUER_AUTH)) {
      throw new IllegalArgumentException("Missing 'issuerAuth' in CredentialDat");
    }
    validateIssuerAuth(docType, credentialDataItem, issuerNamespaces);
  }

  public static PublicKey validateIssuerAuth(String expectedDocType, DataItem credentialDataItem,
      HashMap<String, List<byte[]>> issuerNamespaces) {

    DataItem issuerAuthDataItem = Util.cborMapExtract(credentialDataItem, "issuerAuth");

    List<X509Certificate> issuerAuthorityCertChain = Util.coseSign1GetX5Chain(issuerAuthDataItem);
    if (issuerAuthorityCertChain.size() < 1) {
      throw new IllegalArgumentException("No x5chain element in issuer signature");
    }

    byte[] encodedMobileSecurityObject = Util.cborExtractTaggedCbor(
        Util.coseSign1GetData(issuerAuthDataItem));
    MobileSecurityObjectParser.MobileSecurityObject parsedMso = new MobileSecurityObjectParser().setMobileSecurityObject(
        encodedMobileSecurityObject).parse();

    /* don't care about version for now */
    String digestAlgorithm = parsedMso.getDigestAlgorithm();
    MessageDigest digester;
    try {
      digester = MessageDigest.getInstance(digestAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Failed creating digester");
    }

    String msoDocType = parsedMso.getDocType();
    if (!msoDocType.equals(expectedDocType)) {
      throw new IllegalArgumentException(
          "docType in MSO '" + msoDocType + "' does not match docType from Document");
    }

    Set<String> nameSpaceNames = parsedMso.getValueDigestNamespaces();
    java.util.Map<String, java.util.Map<Long, byte[]>> digestMapping = new HashMap<>();
    for (String nameSpaceName : nameSpaceNames) {
      digestMapping.put(nameSpaceName, parsedMso.getDigestIDs(nameSpaceName));
    }

    PublicKey deviceKey = parsedMso.getDeviceKey();

    for (String nameSpace : issuerNamespaces.keySet()) {
      Map<Long, byte[]> innerDigestMapping = digestMapping.get(nameSpace);
      if (innerDigestMapping == null) {
        throw new IllegalArgumentException("No digestID MSO entry for namespace " + nameSpace);
      }
      List<byte[]> byteArrayList = issuerNamespaces.get(nameSpace);
      for (byte[] byteArr : byteArrayList) {
        DataItem elem = Util.cborDecode(byteArr);
        if (!(elem.hasTag() && elem.getTag().getValue() == 24 && (elem instanceof ByteString))) {
          throw new IllegalArgumentException("issuerSignedItemBytes is not a tagged ByteString");
        }
        // We need the encoded representation with the tag.
        byte[] encodedIssuerSignedItem = ((ByteString) elem).getBytes();
        byte[] encodedIssuerSignedItemBytes = Util.cborEncode(
            Util.cborBuildTaggedByteString(encodedIssuerSignedItem));
        byte[] expectedDigest = digester.digest(encodedIssuerSignedItemBytes);

        DataItem issuerSignedItem = Util.cborExtractTaggedAndEncodedCbor(elem);
        String elementName = Util.cborMapExtractString(issuerSignedItem, "elementIdentifier");
        DataItem elementValue = Util.cborMapExtract(issuerSignedItem, "elementValue");
        long digestId = Util.cborMapExtractNumber(issuerSignedItem, "digestID");

        byte[] digest = innerDigestMapping.get(digestId);
        if (digest == null) {
          throw new IllegalArgumentException(
              "No digestID MSO entry for ID " + digestId + " in namespace " + nameSpace);
        }
        if (!Arrays.equals(expectedDigest, digest)) {
          throw new IllegalArgumentException(
              "Digest mismatch between issuerSignedDataItem and" + "isserAuth for element id:"
                  + elementName);
        }
      }
    }
    return deviceKey;
  }

  public static HashMap<String, List<byte[]>> getIssuerNamespaces(DataItem credentialDataItem) {
    HashMap<String, List<byte[]>> issuerNamespaces = new HashMap<>();
    DataItem namespaceItems = Util.cborMapExtractMap(credentialDataItem,
        CRED_DATA_KEY_ISSUER_NAMESPACES);
    for (String namespace : Util.cborMapExtractMapStringKeys(namespaceItems)) {
      List<DataItem> namespaceList = Util.cborMapExtractArray(namespaceItems, namespace);
      List<byte[]> innerArray = new ArrayList<>();

      for (DataItem innerKey : namespaceList) {
        if (!(innerKey instanceof ByteString)) {
          throw new IllegalArgumentException("Inner key is not a bstr");
        }
        if (innerKey.getTag().getValue() != 24) {
          throw new IllegalArgumentException("Inner key does not have tag 24");
        }
        DataItem issuerSignedItem = Util.cborExtractTaggedAndEncodedCbor(innerKey);
        if (Util.cborMapExtractMapStringKeys(credentialDataItem).size() != 4) {
          throw new IllegalArgumentException("issuerSignedItem must have a size of 4");
        }
        for (String issuerSignedItemKey : Util.cborMapExtractMapStringKeys(issuerSignedItem)) {
          switch (issuerSignedItemKey) {
            case ISSUER_SIGNED_ITEM_KEY_DIGEST_ID:
            case ISSUER_SIGNED_ITEM_KEY_RANDOM:
            case ISSUER_SIGNED_ITEM_KEY_ELE_ID:
            case ISSUER_SIGNED_ITEM_KEY_ELE_VAL:
              break;
            default:
              throw new IllegalArgumentException(
                  "Not a valid key in IssuerSignedItem: " + issuerSignedItemKey);
          }
        }
        innerArray.add(Util.cborEncode(innerKey));
      }
      issuerNamespaces.put(namespace, innerArray);
    }
    return issuerNamespaces;
  }

  private static HashMap<String, List<byte[]>> generateIssuerNamespaces(
      PersonalizationData personalizationData) {
    HashMap<String, List<byte[]>> issuerSignedMapping = new HashMap<>();
    int numEntries = 0;
    for (PersonalizationData.NamespaceData nsd : personalizationData.getNamespaceDatas()) {
      numEntries += nsd.getEntryNames().size();
    }
    List<Long> digestIds = new ArrayList<>();
    for (Long n = 0L; n < numEntries; n++) {
      digestIds.add(n);
    }
    Collections.shuffle(digestIds);

    Random r = new SecureRandom();
    Iterator<Long> digestIt = digestIds.iterator();
    for (PersonalizationData.NamespaceData nsd : personalizationData.getNamespaceDatas()) {
      String ns = nsd.getNamespaceName();

      List<byte[]> innerArray = new ArrayList<>();

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

        byte[] encodedIssuerSignedItemBytes = Util.cborEncode(
            Util.cborBuildTaggedByteString(encodedIssuerSignedItem));

        innerArray.add(encodedIssuerSignedItemBytes);
      }

      issuerSignedMapping.put(ns, innerArray);
    }
    return issuerSignedMapping;
  }

  private static byte[] createMobileSecurityObject(String docType, PublicKey authKey,
      PersonalizationData personalizationData, HashMap<String, List<byte[]>> issuerSignedMapping,
      KeyPair issuerAuthorityKeyPair, X509Certificate issuerAuthorityCertificate) {
    final Timestamp signedDate = Timestamp.now();
    final Timestamp validFromDate = Timestamp.now();
    Calendar validToCalendar = Calendar.getInstance();
    validToCalendar.add(Calendar.MONTH, 12);
    final Timestamp validToDate = Timestamp.ofEpochMilli(validToCalendar.getTimeInMillis());

    MobileSecurityObjectGenerator msoGenerator = new MobileSecurityObjectGenerator("SHA-256",
        docType, authKey).setValidityInfo(signedDate, validFromDate, validToDate, null);

    Map<Long, byte[]> vdInner = new HashMap<>();
    issuerSignedMapping.forEach((ns, issuerSignedItems) -> {
      issuerSignedItems.forEach((encodedIssuerSignedItemBytes) -> {
        try {
          DataItem item = Util.cborExtractTaggedAndEncodedCbor(
              Util.cborDecode(encodedIssuerSignedItemBytes));
          long digestId = Util.cborMapExtractNumber(item, "digestID");
          byte[] digest = MessageDigest.getInstance("SHA-256").digest(encodedIssuerSignedItemBytes);
          vdInner.put(digestId, digest);
        } catch (NoSuchAlgorithmException e) {
          throw new IllegalArgumentException("Failed creating digester", e);
        }
      });
      msoGenerator.addDigestIdsForNamespace(ns, vdInner);
    });
    byte[] encodedMobileSecurityObject = msoGenerator.generate();

    byte[] taggedEncodedMso = Util.cborEncode(
        Util.cborBuildTaggedByteString(encodedMobileSecurityObject));

    ArrayList<X509Certificate> issuerAuthorityCertChain = new ArrayList<>();
    issuerAuthorityCertChain.add(issuerAuthorityCertificate);
    byte[] encodedIssuerAuth = Util.cborEncode(
        Util.coseSign1Sign(issuerAuthorityKeyPair.getPrivate(), "SHA256withECDSA", taggedEncodedMso,
            null, issuerAuthorityCertChain));

    return encodedIssuerAuth;
  }


  public static byte[] getAndFormatRawPublicKey(X509Certificate cert) {
    PublicKey pubKey = cert.getPublicKey();
    if (!(pubKey instanceof ECPublicKey)) {
      return null;
    }
    ECPublicKey key = (ECPublicKey) cert.getPublicKey();
    // s: 1 byte, x: 32 bytes, y: 32 bytes
    BigInteger xCoord = key.getW().getAffineX();
    BigInteger yCoord = key.getW().getAffineY();
    byte[] formattedKey = new byte[65];
    int offset = 0;
    formattedKey[offset++] = 0x04;
    byte[] xBytes = xCoord.toByteArray();
    // BigInteger returns the value as two's complement big endian byte encoding. This means
    // that a positive, 32-byte value with a leading 1 bit will be converted to a byte array of
    // length 33 in order to include a leading 0 bit.
    if (xBytes.length == 33) {
      System.arraycopy(xBytes, 1 /* offset */, formattedKey, offset, 32);
    } else {
      System.arraycopy(xBytes, 0 /* offset */,
          formattedKey, offset + 32 - xBytes.length, xBytes.length);
    }
    byte[] yBytes = yCoord.toByteArray();
    if (yBytes.length == 33) {
      System.arraycopy(yBytes, 1 /* offset */, formattedKey, offset + 32 /* offset */, 32);
    } else {
      System.arraycopy(yBytes, 0 /* offset */,
          formattedKey, offset + 64 - yBytes.length, yBytes.length);
    }
    return formattedKey;
  }

}
