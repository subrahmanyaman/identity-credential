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

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.android.identity.internal.Util;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class DirectAccessCborHelper {
  public static final int KEY_CERT = 0x01;
  public static final int KEY_ENC_DATA = 0x00;

  public PresentationPackage decodePresentationPackage(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("createPresentationPackage failed. Response status: "+ status);
    }
    byte[] input = Arrays.copyOf(response, response.length-2);

    ByteArrayInputStream bai = new ByteArrayInputStream(input);
    CborDecoder decoder = new CborDecoder(bai);
    PresentationPackage pp = null;
    try {
      List<DataItem> items = decoder.decode();
      for (DataItem item : items) {
        if (item.getMajorType() != MajorType.MAP) {
          throw new IllegalStateException("createPresentationPackage response is not cbor map");
        }
        Collection<DataItem> keys = ((Map) item).getKeys();
        pp = new PresentationPackage();
        for (DataItem keyItem : keys) {
          if (keyItem.getMajorType() != MajorType.UNSIGNED_INTEGER) {
            throw new IllegalStateException("createPresentationPackage key item is not uint");
          }
          int value = ((UnsignedInteger) keyItem).getValue().intValue();
          switch (value) {
            case KEY_CERT:
              DataItem bStrItem = ((Map) item).get(keyItem);
              if (bStrItem.getMajorType() != MajorType.BYTE_STRING) {
                throw new IllegalStateException("createPresentationPackage key value is not byte string");
              }
              byte[] certData = ((ByteString) bStrItem).getBytes();
              List<X509Certificate> credentialKeyCert = null;
              try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream bis = new ByteArrayInputStream(certData);
                credentialKeyCert = new ArrayList<>();
                credentialKeyCert.add((X509Certificate) cf.generateCertificate(bis));
              } catch (CertificateException e) {
                throw new IllegalStateException("Error generating signing certificate from response", e);
              }
              pp.signingCert = credentialKeyCert;
              break;
            case KEY_ENC_DATA:
              DataItem encBytesItem = ((Map) item).get(keyItem);
              if (encBytesItem.getMajorType() != MajorType.BYTE_STRING) {
                throw new IllegalStateException("createPresentationPackage key value is not byte string");
              }
              pp.encryptedData = ((ByteString) encBytesItem).getBytes();
              break;
            default:
              throw new IllegalStateException("createPresentationPackage unknown key item");
          }
        }
        return pp;
      }
    } catch (CborException e) {
      throw new IllegalStateException("Failed to parse the createPresentationPackage response", e);
    }
    return null;
  }

  public boolean isOkResponse(byte[] response) {
    int status = getApduStatus(response);
    return DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK == status;
  }

  public List<X509Certificate> decodeCredentialKeyResponse(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("CreateCredential failed. Response status: "+ status);
    }
    byte[] input = Arrays.copyOf(response, response.length-2);
    // TODO DirectAccess Applet returns only one certificate and not chain.
    //  TODO This logic has to be updated if more certificates are returned from Applet.
    List<X509Certificate> credentialKeyCert = null;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(input);
      credentialKeyCert = new ArrayList<>();
      credentialKeyCert.add((X509Certificate) cf.generateCertificate(bis));
    } catch (CertificateException e) {
      throw new IllegalStateException("Error generating certificate from response", e);
    }
    return credentialKeyCert;
  }

  public byte[] decodeProvisionResponse(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("Begin Provision failed. Response status: "+ status);
    }
    if (response.length > 2) {
      byte[] input = Arrays.copyOf(response, response.length - 2);
      return Util.cborDecodeByteString(input);
    }
    return null;
  }

  public void decodeDeleteCredential(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("createPresentationPackage failed. Response status: "+ status);
    }
  }

  private int getApduStatus(byte[] cborResponse) {
    // TODO Move this a common place in Transport.
    DirectAccessAPDUHelper apduHelper = new DirectAccessAPDUHelper();
    return apduHelper.getAPDUResponseStatus(cborResponse);
  }

}
