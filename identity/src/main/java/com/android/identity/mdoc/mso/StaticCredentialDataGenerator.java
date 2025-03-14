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

package com.android.identity.mdoc.mso;

import androidx.annotation.NonNull;
import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;
import com.android.identity.internal.Util;
import com.android.identity.util.Logger;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class StaticCredentialDataGenerator {

    private Map<String, List<byte[]>> mDigestIDMapping = new HashMap<>();
    private byte[] mEncodedIssuerAuth;
    private List<X509Certificate> mReaderCerts;
    private String mDocType;

    /**
     * Constructs a new {@link StaticCredentialDataGenerator}.
     *
     * @param digestIDMapping A non-empty mapping between a <code>Namespace</code> and a list of
     *                        <code>IssuerSignedItemMetadataBytes</code>.
     * @param encodedIssuerAuth A COSE_Sign1 object with a payload of MobileSecurityObjectBytes.
     * @exception IllegalArgumentException if the <code>digestIDMapping</code> is empty.
     */
    public StaticCredentialDataGenerator(@NonNull Map<String, List<byte[]>> digestIDMapping,
                                   @NonNull byte[] encodedIssuerAuth,
        String docType,
        List<X509Certificate> readerCerts) {
        if (digestIDMapping.isEmpty()) {
            throw new IllegalArgumentException("digestIDs must not be empty");
        }
        mDigestIDMapping = digestIDMapping;
        mEncodedIssuerAuth = encodedIssuerAuth;
        mDocType = docType;
        mReaderCerts = readerCerts;
    }

    /**
     * Builds the <code>StaticCredentialData</code> CBOR.
     *
     * @return the bytes of <code>StaticCredentialData</code> CBOR.
     */
    @NonNull
    public byte[] generate() {
        CborBuilder digestIdBuilder = new CborBuilder();
        MapBuilder<CborBuilder> outerBuilder = digestIdBuilder.addMap();
        for (String namespace : mDigestIDMapping.keySet()) {
            ArrayBuilder<MapBuilder<CborBuilder>> innerBuilder = outerBuilder.putArray(namespace);

            for (byte[] encodedIssuerSignedItemMetadata : mDigestIDMapping.get(namespace)) {
                innerBuilder.add(Util.cborDecode(encodedIssuerSignedItemMetadata));
            }
        }
        DataItem digestIdMappingItem = digestIdBuilder.build().get(0);

        ArrayBuilder<CborBuilder> readerBuilder = new CborBuilder().addArray();
        if (mReaderCerts != null) {
            for (X509Certificate cert : mReaderCerts) {
                byte[] pubKey = getAndFormatRawPublicKey(cert);
                //readerBuilder.add(pubKey);
            }
        }
        DataItem readerAuth = readerBuilder.end().build().get(0);
        byte[] staticCredentialData = Util.cborEncode(
            new CborBuilder().addMap().put(new UnicodeString("docType"), new UnicodeString(mDocType))
                .put(new UnicodeString("issuerNameSpaces"), digestIdMappingItem)
                .put(new UnicodeString("issuerAuth"), Util.cborDecode(mEncodedIssuerAuth))
                .put(new UnicodeString("readerAccess"), readerAuth)
                .end().build().get(0));
        return staticCredentialData;
    }

    private byte[] getAndFormatRawPublicKey(X509Certificate cert) {
        PublicKey pubKey = cert.getPublicKey();
        if (!(pubKey instanceof ECPublicKey)) {
            return null;
        }
        ECPublicKey key = (ECPublicKey) cert.getPublicKey();
        BigInteger xCoord = key.getW().getAffineX();
        BigInteger yCoord = key.getW().getAffineY();
        Logger.d("StaticCredentialDataGenerator", " Algorithm:"+pubKey.getAlgorithm());
        int keySize = 0;
        if ("EC".equals(pubKey.getAlgorithm())) {
            Logger.d("StaticCredentialDataGenerator",
                " ECCurve:"+((ECPublicKey) pubKey).getParams().getCurve().getField().getFieldSize());
            int curve = ((ECPublicKey) pubKey).getParams().getCurve().getField().getFieldSize();
            switch (curve) {
                case 256:
                    keySize = 32;
                    break;
                case 384:
                    keySize = 48;
                    break;
                case 521:
                    keySize = 66;
                    break;
                case 512:
                    keySize = 65;
                    break;
            }
            Logger.d("StaticCredentialDataGenerator", "Expected: "+keySize
                +"  X-Actual: "+((ECPublicKey) pubKey).getW().getAffineX().bitLength()
                +"  Y-Actual: "+((ECPublicKey) pubKey).getW().getAffineY().bitLength());
        } else {
            // TODO Handle other Algorithms
        }
        ByteBuffer bb = ByteBuffer.allocate((keySize*2) +1);
        Arrays.fill(bb.array(), (byte)0);
        bb.put((byte) 0x04);
        byte[] xBytes = xCoord.toByteArray();
        // BigInteger returns the value as two's complement big endian byte encoding. This means
        // that a positive, 32-byte value with a leading 1 bit will be converted to a byte array of
        // length 33 in order to include a leading 0 bit.
        if (xBytes.length == (keySize + 1)){
            bb.put(xBytes, 0,  keySize);
        } else {
            bb.position(bb.position()+ keySize - xBytes.length);
            bb.put(xBytes, 0, xBytes.length);
        }
        byte[] yBytes = yCoord.toByteArray();
        if (yBytes.length == (keySize + 1)) {
            bb.put(yBytes, 0,  keySize);
        } else {
            bb.position(bb.position()+ keySize - yBytes.length);
            bb.put(yBytes, 0, yBytes.length);
        }
        return bb.array();
    }
}
