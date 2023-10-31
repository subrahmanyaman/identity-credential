package com.android.identity.android.direct_access;

import java.io.IOException;

public interface DirectAccessTransport {

  void openConnection() throws IOException;

  byte[] sendData(byte[] input) throws IOException;

  void closeConnection() throws IOException;

  boolean isConnected() throws IOException;

  int getMaxTransceiveLength();

}
