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

import android.se.omapi.Channel;
import android.se.omapi.Reader;
import android.se.omapi.SEService;
import android.se.omapi.Session;

import com.android.identity.direct_access.DirectAccessTransport;

import java.io.IOException;
import java.util.Arrays;

public class DirectAccessOmapiTransport implements DirectAccessTransport {
  public static final String TAG = "DirectAccessOmapiTransport";
  private static final byte DIRECT_ACCESS_CHANNEL = 0;
  private static final String ESE_READER = "eSE1";
  private SEService mSEService;
  private byte[] mProvisionAppletAid;
  private Channel mEseChannel;
  private Reader mEseReader;
  private Session mEseSession;


  public DirectAccessOmapiTransport(SEService service, byte[] provisionAppletAid) {
    mSEService = service;
    mProvisionAppletAid = provisionAppletAid;
  }

  @Override
  public void init() throws IOException {
  }

  @Override
  public void openConnection() throws IOException {
    if (!isConnected()) {
      initialize(mProvisionAppletAid);
    }
  }

  private boolean isSelectApdu(byte[] input) {
    if ((input[1] == (byte) 0xA4) && (input[2] == (byte) 0x04)) {
      return true;
    }
    return false;
  }

  private byte[] getAid(byte[] input) {
    byte length = input[4];
    byte[] aid = Arrays.copyOfRange(input, 5, 5+length);
    return aid;
  }

  @Override
  public byte[] sendData(byte[] input) throws IOException {
    if (isSelectApdu(input)) {
      // Close existing channel and open basic channel again
      closeConnection();
      initialize(getAid(input));
      return new byte[] {(byte) 0x90, 0x00};
    } else {
      if (!isConnected()) {
        initialize(mProvisionAppletAid);
      }
    }
    return transceive(input);
  }

  @Override
  public void closeConnection() throws IOException {
    reset();
  }

  @Override
  public boolean isConnected() throws IOException {
    if (mEseChannel == null) {
      return false;
    }
    return mEseChannel.isOpen();
  }

  @Override
  public int getMaxTransceiveLength() {
    // TODO
    // This value is set based on Pixel's eSE APDU Buffer size.
    return 261;
  }

  @Override
  public void unInit() throws IOException {

  }


  private Reader getEseReader() {
    if (mSEService == null) {
      return null;
    }
    Reader[] readers = mSEService.getReaders();
    for (Reader reader : readers) {
      if (ESE_READER.equals(reader.getName())) {
        return reader;
      }
    }
    return null;
  }

  private void reset() {
    if (mEseChannel != null) {
      mEseChannel.close();
      mEseChannel = null;
    }
    if (mEseSession != null) {
      mEseSession.close();
      mEseSession = null;
    }
    if (mEseReader != null) {
      mEseReader.closeSessions();
      mEseReader = null;
    }
  }

  private void initialize(byte[] aid) throws IOException {
    reset();
    mEseReader = getEseReader();
    if (mEseReader == null) {
      throw new IOException("eSE reader not available");
    }

    if (!mEseReader.isSecureElementPresent()) {
      throw new IOException("Secure Element not present");
    }

    mEseSession = mEseReader.openSession();
    if (mEseSession == null) {
      throw new IOException("Could not open session.");
    }
    mEseChannel = mEseSession.openBasicChannel(aid);
    if (mEseChannel == null) {
      throw new IOException("Could not open channel.");
    }
  }

  private byte[] transceive(byte[] input) throws IOException {
    byte[] selectResponse = mEseChannel.getSelectResponse();
    if ((selectResponse.length < 2) ||
        ((selectResponse[selectResponse.length - 1] & 0xFF) != 0x00) ||
        ((selectResponse[selectResponse.length - 2] & 0xFF) != 0x90)) {
      return null;
    }
    return mEseChannel.transmit(input);
  }
}
