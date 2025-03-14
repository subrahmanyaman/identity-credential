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

package com.android.identity.mdoc.util;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.identity.credential.CredentialRequest;
import com.android.identity.internal.Util;
import com.android.identity.credential.NameSpacedData;
import com.android.identity.mdoc.mso.StaticAuthDataParser;
import com.android.identity.mdoc.request.DeviceRequestParser;
import com.android.identity.util.Logger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * Utilities for working with MDOC data structures.
 *
 * <p>On the issuance-side, {@link #generateIssuerNameSpaces(NameSpacedData, Random, int)}
 * and {@link #stripIssuerNameSpaces(Map)} can be used with {@link com.android.identity.mdoc.mso.MobileSecurityObjectGenerator}
 * and {@link #calculateDigestsForNameSpace(String, Map, String)} can be used to prepare
 * PII and multiple static authentication data packages (each including signed MSOs).
 *
 * <p>On the device-side, {@link #mergeIssuerNamesSpaces(CredentialRequest, NameSpacedData, StaticAuthDataParser.StaticAuthData)}
 * can be used to generate the {@code DeviceResponse} CBOR from the above-mentioned PII
 * and static authentication data packages.
 */
public class MdocUtil {

    private static final String TAG = "MdocUtil";

    /**
     * Generates randoms and digest identifiers for data.
     *
     * <p>This generates data similar to {@code IssuerNameSpaces} CBOR as defined in ISO 18013-5:
     *
     * <pre>
     * IssuerNameSpaces = { ; Returned data elements for each namespace
     *   + NameSpace =&gt; [ + IssuerSignedItemBytes ]
     * }
     *
     * IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
     *
     * IssuerSignedItem = {
     *   "digestID" : uint, ; Digest ID for issuer data authentication
     *   "random" : bstr, ; Random value for issuer data authentication
     *   "elementIdentifier" : DataElementIdentifier, ; Data element identifier
     *   "elementValue" : DataElementValue ; Data element value
     * }
     * </pre>
     *
     * <p>except that the data is returned using a native maps and lists. The returned
     * data is a map from name spaces into a list of the bytes of the
     * {@code IssuerSignedItemBytes} CBOR. The digest identifies and randoms are
     * generated by this helper using the provided {@link Random} provider.
     *
     * @param data The name spaced data.
     * @param randomProvider A random provider used for generating digest identifiers and salts.
     * @param dataElementRandomSize The number of bytes to use for the salt for each data elements,
     *                              must be at least 16.
     * @param overrides Optionally, a map of namespaces into data element names into values for
     *                  overriding data in the provided {@link NameSpacedData} parameter.
     * @return The data described above.
     * @throws IllegalArgumentException if {@code dataElementRandomSize} is less than 16.
     */
    public static @NonNull Map<String, List<byte[]>> generateIssuerNameSpaces(
            @NonNull NameSpacedData data,
            @NonNull Random randomProvider,
            int dataElementRandomSize,
            @Nullable Map<String, Map<String, byte[]>> overrides) {

        if (dataElementRandomSize < 16) {
            // ISO 18013-5 section 9.1.2.5 Message digest function says that random must
            // be at least 16 bytes long.
            throw new IllegalArgumentException("Random size must be at least 16 bytes");
        }

        LinkedHashMap<String, List<byte[]>> ret = new LinkedHashMap<>();

        // Count number of data elements first.
        int numDataElements = 0;
        for (String nsName : data.getNameSpaceNames()) {
            numDataElements += data.getDataElementNames(nsName).size();
        }
        List<Long> digestIds = new ArrayList<>();
        for (long n = 0L; n < numDataElements; n++) {
            digestIds.add(n);
        }
        Collections.shuffle(digestIds, randomProvider);

        Iterator<Long> digestIt = digestIds.iterator();
        for (String nsName : data.getNameSpaceNames()) {

            Map<String, byte[]> overridesByNameSpace = null;
            if (overrides != null) {
                overridesByNameSpace = overrides.get(nsName);
            }

            List<byte[]> list = new ArrayList<>();
            for (String elemName : data.getDataElementNames(nsName)) {

                byte[] encodedValue = data.getDataElement(nsName, elemName);
                long digestId = digestIt.next();
                byte[] random = new byte[dataElementRandomSize];
                randomProvider.nextBytes(random);

                if (overridesByNameSpace != null) {
                    byte[] overriddenValue = overridesByNameSpace.get(elemName);
                    if (overriddenValue != null) {
                        encodedValue = overriddenValue;
                    }
                }

                DataItem value = Util.cborDecode(encodedValue);

                DataItem issuerSignedItem = new CborBuilder()
                        .addMap()
                        .put("digestID", digestId)
                        .put("random", random)
                        .put("elementIdentifier", elemName)
                        .put(new UnicodeString("elementValue"), value)
                        .end()
                        .build().get(0);
                byte[] encodedIssuerSignedItem = Util.cborEncode(issuerSignedItem);

                byte[] encodedIssuerSignedItemBytes =
                        Util.cborEncode(Util.cborBuildTaggedByteString(
                                encodedIssuerSignedItem));

                list.add(encodedIssuerSignedItemBytes);
            }
            ret.put(nsName, list);
        }
        return ret;
    }

    /**
     * Strips issuer name spaces.
     *
     * <p>This takes a {@code IssuerNameSpaces} value calculated by
     * {@link #generateIssuerNameSpaces(NameSpacedData, Random, int)}
     * and returns a similar structure except where all {@code elementValue} values
     * in {@code IssuerSignedItem} are set to {@code null}.
     *
     * @param issuerNameSpaces a map from name spaces into a list of {@code IssuerSignedItemBytes}.
     * @param exceptions a map from name spaces into a list of data element names for where
     *                   the {@code elementValue} should not be removed.
     * @return A copy of the passed-in structure where data element value is set to {@code null}.
     *         for every data element.
     */
    public static @NonNull Map<String, List<byte[]>> stripIssuerNameSpaces(
            @NonNull Map<String, List<byte[]>> issuerNameSpaces,
            @Nullable Map<String, List<String>> exceptions) {
        Map<String, List<byte[]>> ret = new LinkedHashMap<>();

        for (String nameSpaceName : issuerNameSpaces.keySet()) {
            List<byte[]> list = new ArrayList<>();

            List<String> exceptionsForNamespace = null;
            if (exceptions != null) {
                exceptionsForNamespace = exceptions.get(nameSpaceName);
            }
            for (byte[] encodedIssuerSignedItemBytes : issuerNameSpaces.get(nameSpaceName)) {
                byte[] encodedIssuerSignedItem = Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes);

                if (exceptionsForNamespace != null) {
                    DataItem item = Util.cborDecode(encodedIssuerSignedItem);
                    String elementIdentifier = Util.cborMapExtractString(item, "elementIdentifier");
                    if (exceptionsForNamespace.contains(elementIdentifier)) {
                        list.add(encodedIssuerSignedItemBytes);
                        continue;
                    }
                }

                byte[] modifiedEncodedIssuerSignedItem = Util.issuerSignedItemClearValue(encodedIssuerSignedItem);
                byte[] modifiedEncodedIssuerSignedItemBytes = Util.cborEncode(
                        Util.cborBuildTaggedByteString(modifiedEncodedIssuerSignedItem));
                list.add(modifiedEncodedIssuerSignedItemBytes);
            }
            ret.put(nameSpaceName, list);
        }
        return ret;
    }

    /**
     * Calculates all digests in a given name space.
     *
     * @param nameSpaceName the name space to pick from the {@code issuerNameSpaces} map.
     * @param issuerNameSpaces a map from name spaces into a list of {@code IssuerSignedItemBytes}.
     * @param digestAlgorithm the digest algorithm to use, for example {@code SHA-256}.
     * @return a map from digest identifiers to the calculated digest.
     * @throws IllegalArgumentException if the digest algorithm isn't supported.
     */
    public static @NonNull
    Map<Long, byte[]> calculateDigestsForNameSpace(@NonNull String nameSpaceName,
                                                   @NonNull Map<String, List<byte[]>> issuerNameSpaces,
                                                   @NonNull String digestAlgorithm) {
        List<byte[]> list = issuerNameSpaces.get(nameSpaceName);
        if (list == null) {
            throw new IllegalArgumentException("No namespace " + nameSpaceName + " in IssuerNameSpaces");
        }
        Map<Long, byte[]> ret = new LinkedHashMap<>();
        for (byte[] encodedIssuerSignedItemBytes : list) {
            DataItem map = Util.cborDecode(Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes));
            long digestId = Util.cborMapExtractNumber(map, "digestID");
            try {
                byte[] digest = MessageDigest.getInstance(digestAlgorithm).digest(encodedIssuerSignedItemBytes);
                ret.put(digestId, digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("Failed creating digester", e);
            }
        }
        return ret;
    }

    // Note: this also unwraps the bstr tagging of the IssuerSignedItem!
    private static @NonNull
    Map<String, Map<String, byte[]>> calcIssuerSignedItemMap(
            @NonNull  Map<String, List<byte[]>> issuerNameSpaces) {
        Map<String, Map<String, byte[]>> ret = new LinkedHashMap<>();
        for (String nameSpaceName : issuerNameSpaces.keySet()) {
            Map<String, byte[]> innerMap = new LinkedHashMap<>();
            for (byte[] encodedIssuerSignedItemBytes : issuerNameSpaces.get(nameSpaceName)) {
                byte[] encodedIssuerSignedItem = Util.cborExtractTaggedCbor(encodedIssuerSignedItemBytes);
                DataItem map = Util.cborDecode(encodedIssuerSignedItem);
                String elementIdentifier = Util.cborMapExtractString(map, "elementIdentifier");
                innerMap.put(elementIdentifier, encodedIssuerSignedItem);
            }
            ret.put(nameSpaceName, innerMap);
        }
        return ret;
    }

    private static @Nullable
    byte[] lookupIssuerSignedMap(@NonNull Map<String, Map<String, byte[]>> issuerSignedMap,
                                 @NonNull String nameSpaceName,
                                 @NonNull String dataElementName) {
        Map<String, byte[]> innerMap = issuerSignedMap.get(nameSpaceName);
        if (innerMap == null) {
            return null;
        }
        return innerMap.get(dataElementName);
    }

    /**
     * Combines credential data with static authentication data for a given request.
     *
     * <p>This goes through all data element name in a given {@link CredentialRequest} and
     * for each data element name, looks up {@code credentialData} and {@code staticAuthData}
     * for the value and if present, will include that in the result. Data elements with
     * {@link CredentialRequest.DataElement#getDoNotSend()} returning {@code true} are
     * ignored.
     *
     * <p>The result is intended to mimic {@code IssuerNameSpaces} CBOR as defined
     * in ISO 18013-5 except that the data is returned using a native maps and lists.
     * The returned data is a map from name spaces into a list of the bytes of the
     * {@code IssuerSignedItemBytes} CBOR.
     *
     * @param request a {@link CredentialRequest} indicating which name spaces and data
     *                element names to include in the result.
     * @param credentialData Credential data, organized by name space.
     * @param staticAuthData Static authentication data.
     * @return A map described above.
     */
    public static @NonNull
    Map<String, List<byte[]>> mergeIssuerNamesSpaces(
            @NonNull CredentialRequest request,
            @NonNull NameSpacedData credentialData,
            @NonNull StaticAuthDataParser.StaticAuthData staticAuthData) {

        Map<String, Map<String, byte[]>> issuerSignedItemMap =
                calcIssuerSignedItemMap(staticAuthData.getDigestIdMapping());

        Map<String, List<byte[]>> issuerSignedData = new LinkedHashMap<>();
        for (CredentialRequest.DataElement element : request.getRequestedDataElements()) {
            if (element.getDoNotSend()) {
                continue;
            }
            String nameSpaceName = element.getNameSpaceName();
            String dataElementName = element.getDataElementName();
            if (!credentialData.hasDataElement(nameSpaceName, dataElementName)) {
                Logger.d(TAG, "No data element in credential for nameSpace "
                        + nameSpaceName + " dataElementName " + dataElementName);
                continue;
            }
            byte[] value = credentialData.getDataElement(nameSpaceName, dataElementName);

            byte[] encodedIssuerSignedItemMaybeWithoutValue =
                    lookupIssuerSignedMap(issuerSignedItemMap, nameSpaceName, dataElementName);
            if (encodedIssuerSignedItemMaybeWithoutValue == null) {
                Logger.w(TAG, "No IssuerSignedItem for " + nameSpaceName + " " + dataElementName);
                continue;
            }

            byte[] encodedIssuerSignedItem;
            if (hasElementValue(encodedIssuerSignedItemMaybeWithoutValue)) {
                encodedIssuerSignedItem = encodedIssuerSignedItemMaybeWithoutValue;
            } else {
                encodedIssuerSignedItem = Util.issuerSignedItemSetValue(encodedIssuerSignedItemMaybeWithoutValue, value);
            }

            List<byte[]> list = issuerSignedData.computeIfAbsent(element.getNameSpaceName(), k -> new ArrayList<>());

            // We need a tagged bstr here
            byte[] taggedEncodedIssuerSignedItem = Util.cborEncode(Util.cborBuildTaggedByteString(encodedIssuerSignedItem));
            list.add(taggedEncodedIssuerSignedItem);
        }
        return issuerSignedData;
    }

    private static boolean hasElementValue(byte[] encodedIssuerSignedItem) {
        DataItem issuerSignedItem = Util.cborDecode(encodedIssuerSignedItem);
        DataItem elementValue = Util.cborMapExtract(issuerSignedItem, "elementValue");
        if (elementValue instanceof SimpleValue) {
            SimpleValue simpleValue = (SimpleValue) elementValue;
            if (simpleValue.getSimpleValueType() == SimpleValueType.NULL) {
                return false;
            }
        }
        return true;
    }

    /**
     * Helper function to generate a {@link CredentialRequest}.
     *
     * @param documentRequest a {@link com.android.identity.mdoc.request.DeviceRequestParser.DocumentRequest}.
     * @return a {@link CredentialRequest} representing for the given {@link com.android.identity.mdoc.request.DeviceRequestParser.DocumentRequest}.
     */
    public static
    @NonNull CredentialRequest generateCredentialRequest(
            @NonNull DeviceRequestParser.DocumentRequest documentRequest) {
        List<CredentialRequest.DataElement> elements = new ArrayList<>();
        for (String namespaceName : documentRequest.getNamespaces()) {
            for (String dataElementName : documentRequest.getEntryNames(namespaceName)) {
                boolean intentToRetain = documentRequest.getIntentToRetain(namespaceName, dataElementName);
                elements.add(new CredentialRequest.DataElement(namespaceName, dataElementName, intentToRetain));
            }
        }
        return new CredentialRequest(elements);
    }
}
