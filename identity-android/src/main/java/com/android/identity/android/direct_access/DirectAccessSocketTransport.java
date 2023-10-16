package com.android.identity.android.direct_access;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class DirectAccessSocketTransport implements DirectAccessTransport {

  private static final int PORT = 8080;
  private static final String IPADDR = "192.168.9.112";
  private static final int MAX_RECV_BUFFER_SIZE = 2500;
  private Socket mSocket;
  private boolean socketStatus;

  @Override
  public void openConnection() throws IOException {
    InetAddress serverAddress = InetAddress.getByName(IPADDR);
    mSocket = new Socket(serverAddress, PORT);
    socketStatus = true;
  }

  @Override
  public byte[] sendData(byte[] inData) throws IOException {
    int count = 1;
    while (!socketStatus && count++ < 5) {
      try {
        Thread.sleep(1000);
        System.out.println("SocketTransport Trying to open socket connection... count: " + count);
        openConnection();
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }

    if (count >= 5) {
      System.out.println("SocketTransport Failed to open socket connection");
      return null;
    }

    // Prepend the input length to the inputData before sending.
    byte[] length = new byte[2];
    length[0] = (byte) ((inData.length >> 8) & 0xFF);
    length[1] = (byte) (inData.length & 0xFF);

    try {
      ByteArrayOutputStream bs = new ByteArrayOutputStream();
      bs.write(length);
      bs.write(inData);
      OutputStream outputStream = mSocket.getOutputStream();
      outputStream.write(bs.toByteArray());
      outputStream.flush();
    } catch (IOException e) {
      System.out.println(
          "SocketTransport Failed to send data over socket. Error: " + e.getMessage());
      return null;
    }

    return readData();
  }

  @Override
  public void closeConnection() throws IOException {
    mSocket.close();
    socketStatus = false;
  }

  @Override
  public boolean isConnected() throws IOException {
    return socketStatus;
  }

  private byte[] readData() {
    byte[] buffer = new byte[MAX_RECV_BUFFER_SIZE];
    short expectedResponseLen = 0;
    int totalBytesRead = 0;
    ByteArrayOutputStream bs = new ByteArrayOutputStream();

    try {
      do {
        short offset = 0;
        InputStream inputStream = mSocket.getInputStream();
        int numBytes = inputStream.read(buffer, 0, MAX_RECV_BUFFER_SIZE);
        if (numBytes < 0) {
          System.out.println("SocketTransport Failed to read data from socket.");
          return null;
        }
        totalBytesRead += numBytes;
        if (expectedResponseLen == 0) {
          expectedResponseLen |= (buffer[1] & 0xFF);
          expectedResponseLen |= ((buffer[0] << 8) & 0xFF00);
          expectedResponseLen += 2;
          numBytes -= 2;
          offset = 2;
        }
        bs.write(buffer, offset, numBytes);
      } while (totalBytesRead < expectedResponseLen);
      return bs.toByteArray();
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }
}
