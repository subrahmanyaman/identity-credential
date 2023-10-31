package com.android.identity.android.direct_access;

import android.se.omapi.Channel;
import android.se.omapi.Reader;
import android.se.omapi.SEService;
import android.se.omapi.Session;
import java.io.IOException;

public class DirectAccessOmapiTransport implements DirectAccessTransport {


  private static final byte[] DIRECT_ACCESS_APPLET_AID = {};
  private static final byte DIRECT_ACCESS_CHANNEL = 0;
  private static final String ESE_READER = "eSE";
  private SEService mSEService;
  private Channel mEseChannel;
  private Reader mEseReader;
  private Session mEseSession;


  public DirectAccessOmapiTransport(SEService service) {
    mSEService = service;
  }

  @Override
  public void openConnection() throws IOException {
    if (!isConnected()) {
      initialize();
    }
  }

  @Override
  public byte[] sendData(byte[] input) throws IOException {
    if (!isConnected()) {
      initialize();
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
    return 1024;
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

  private void initialize() throws IOException {
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
    mEseChannel = mEseSession.openLogicalChannel(DIRECT_ACCESS_APPLET_AID, DIRECT_ACCESS_CHANNEL);
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
