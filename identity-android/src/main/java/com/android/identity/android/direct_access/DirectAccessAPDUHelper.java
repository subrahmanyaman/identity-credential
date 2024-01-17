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

import androidx.annotation.NonNull;
import com.android.identity.internal.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.time.Duration;
import java.util.Calendar;
import org.bouncycastle.asn1.ASN1UTCTime;

public class DirectAccessAPDUHelper {
  public static final int CMD_MDOC_CREATE = 0x01;
  public static final int CMD_MDOC_CREATE_PRESENTATION_PKG = 0x07;
  public static final int CMD_MDOC_DELETE_CREDENTIAL = 0x08;
  public static final int CMD_MDOC_PROVISION_DATA = 0x09;

  public static final int CMD_MDOC_SWAP_IN = 0x06;
  public final static byte INS_ENVELOPE = (byte) 0xC3;
  public static final int APDU_RESPONSE_STATUS_OK = 0x9000;

  private void setShort(byte[] buf, int offset, short value) {
    buf[offset] = (byte) ((value >> 8) & 0xFF);
    buf[offset + 1] = (byte) (value & 0xFF);
  }

  private byte[] longToByteArray(long val) {
    ByteBuffer bb = ByteBuffer.allocate(8);
    bb.putLong(val);
    return bb.array();
  }

  private byte[] intToByteArray(int val) {
    ByteBuffer bb = ByteBuffer.allocate(4);
    bb.putInt(val);
    return bb.array();
  }

  private byte[] makeCommandApdu(byte ins, byte[] data) throws IOException {
    // TODO Handle non extended length.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(0); // CLS
    bos.write(ins); // INS
    bos.write(0); // P1
    bos.write(0); // P2
    // Send extended length APDU always as response size is not known to HAL.
    // Case 1: Lc > 0  CLS | INS | P1 | P2 | 00 | 2 bytes of Lc | CommandData | 2 bytes of Le
    // all set to 00.
    // Case 2: Lc = 0  CLS | INS | P1 | P2 | 3 bytes of Le all set to 00.
    bos.write(0x00);
    // Extended length 3 bytes, starts with 0x00
    if (data.length > 0) {
      bos.write(data.length >> 8);
      bos.write(data.length & 0xFF);
      // Data
      bos.write(data);
    }
    bos.write(0);
    bos.write(0);
    return bos.toByteArray();
  }

  private byte[] makeCommandApdu(byte[] data) throws IOException {
    return makeCommandApdu(INS_ENVELOPE, data);
  }

  public int getAPDUResponseStatus(@NonNull byte[] input) {
    // Last two bytes are the status SW0SW1
    byte SW0 = input[input.length - 2];
    byte SW1 = input[input.length - 1];
    return (SW0 << 8 | SW1) & 0xFFFF;
  }

  public byte[] encodeValidityTime(long milliseconds) throws IOException {
    Calendar calendar = Calendar.getInstance();
    calendar.setTimeInMillis(milliseconds);
    String formatStr = "yyMMddHHmmss'Z'";
    if (calendar.get(Calendar.YEAR) >= 2050) {
      formatStr = "yyyyMMddHHmmss'Z'";
    }
    SimpleDateFormat sdf = new SimpleDateFormat(formatStr);
    String str = sdf.format(calendar.getTime());
    System.out.println(str);
    ASN1UTCTime asn1UtcTime = new ASN1UTCTime(str);
    return asn1UtcTime.getEncoded();
  }
  private static final byte[] notBefore1 = {
      0x17, 0x0D, 0x31, 0x36, 0x30, 0x31,
      0x31, 0x31, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A};
  //notAfter Time UTCTime 2026-01-08 00:46:09 UTC
  private static final byte[] notAfter1 = {
      0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30,
      0x38, 0x30, 0x30, 0x34, 0x36, 0x30, 0x39, 0x5A};

  public byte[] createCredentialAPDU(int slot, byte[] challenge, long notBefore, long notAfter) throws IOException {
    int osVersion = 2;
    int systemPatchLevel = 2;
    byte[] attAppId = new byte[] {0x00};
    byte[] scratchpad = new byte[2];

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // set instruction
    setShort(scratchpad, 0, (short) CMD_MDOC_CREATE);
    bos.write(scratchpad);
    // set slot
    bos.write(slot);
    // TODO Currently there is no way to provision the test credential.
    // set non-test credential
    bos.write(0);

    byte[] osVersionBytes = intToByteArray(osVersion);
    byte[] patchLevelBytes = intToByteArray(systemPatchLevel);

    // Set OS Version
    setShort(scratchpad, 0, (short) osVersionBytes.length);
    bos.write(scratchpad);
    bos.write(osVersionBytes);

    // Set System patch level
    setShort(scratchpad, 0, (short) patchLevelBytes.length);
    bos.write(scratchpad);
    bos.write(patchLevelBytes);

    // set challenge
    setShort(scratchpad, 0, (short) challenge.length);
    bos.write(scratchpad);
    bos.write(challenge);

    byte[] notBeforeBytes = encodeValidityTime(notBefore);
    byte[] notAfterBytes = encodeValidityTime(notAfter);

    // Set Not Before
    setShort(scratchpad, 0, (short) notBeforeBytes.length);
    bos.write(scratchpad);
    bos.write(notBeforeBytes);

    // Set Not After
    setShort(scratchpad, 0, (short) notAfterBytes.length);
    bos.write(scratchpad);
    bos.write(notAfterBytes);

    // Set creation time
    long creationTimeMs = System.currentTimeMillis();
    byte[] creationTimeMsBytes = longToByteArray(creationTimeMs);
    setShort(scratchpad, 0, (short) creationTimeMsBytes.length);
    bos.write(scratchpad);
    bos.write(creationTimeMsBytes);

    // set attestation application id
    setShort(scratchpad, 0, (short) attAppId.length);
    bos.write(scratchpad);
    bos.write(attAppId);
    byte[] result = bos.toByteArray();
    System.out.println("MDOC_REQUEST:<><><============<><><>");
    print(result, (short) 0, (short) result.length);

    return makeCommandApdu(bos.toByteArray());
  }

  public byte[] createPresentationPackageAPDU(int slot, Duration duration) throws IOException {
    long notBefore = System.currentTimeMillis();
    long notAfter = System.currentTimeMillis() + duration.toMillis();
    byte[] scratchpad = new byte[2];

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // set instruction
    setShort(scratchpad, 0, (short) CMD_MDOC_CREATE_PRESENTATION_PKG);
    bos.write(scratchpad);

    bos.write(slot);

    byte[] notBeforeBytes = encodeValidityTime(notBefore);
    byte[] notAfterBytes = encodeValidityTime(notAfter);

    // Set Not Before
    setShort(scratchpad, 0, (short) notBeforeBytes.length);
    bos.write(scratchpad);
    bos.write(notBeforeBytes);

    // Set Not After
    setShort(scratchpad, 0, (short) notAfterBytes.length);
    bos.write(scratchpad);
    bos.write(notAfterBytes);

    return makeCommandApdu(bos.toByteArray());
  }

  public byte[] createProvisionSwapInApdu(int cmd, int slot, byte[] data, int offset, int length, byte operation) throws IOException {
    ByteBuffer bb = ByteBuffer.allocate(length);
    bb.put(data, offset, length);
    byte[] scratchpad = new byte[2];

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // set instruction
    setShort(scratchpad, 0, (short) cmd);
    bos.write(scratchpad);

    bos.write(slot);
    bos.write(operation);

    bos.write(Util.cborEncodeBytestring(bb.array()));
    return makeCommandApdu(bos.toByteArray());
  }

  public byte[] deleteMDocAPDU(int slot) throws IOException {
    byte[] scratchpad = new byte[2];

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // set instruction
    setShort(scratchpad, 0, (short) CMD_MDOC_DELETE_CREDENTIAL);
    bos.write(scratchpad);

    bos.write(slot);
    return makeCommandApdu(bos.toByteArray());
  }


  // Used for only testing purpose.
  public byte[] createFactoryProvisionApdu(byte ins, short tagCert, byte[] certData,
      short tagKey, byte[] keyData) throws IOException {
    byte[] scratchpad = new byte[2];

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // set Tag cert
    setShort(scratchpad, 0, tagCert);
    bos.write(scratchpad);

    // set cert length
    setShort(scratchpad, 0, (short) certData.length);

    // set cert data
    bos.write(certData);

    // set tag key
    setShort(scratchpad, 0, tagKey);
    bos.write(scratchpad);

    // set key length
    setShort(scratchpad, 0, (short) keyData.length);

    // set cert data
    bos.write(keyData);

    return makeCommandApdu(ins, bos.toByteArray());
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
