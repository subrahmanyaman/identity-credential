package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import android.content.Context;
import android.se.omapi.SEService;
import android.se.omapi.SEService.OnConnectedListener;
import android.util.Log;
import androidx.test.platform.app.InstrumentationRegistry;
import com.android.identity.android.storage.AndroidStorageEngine;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Logger;
import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import org.junit.Assert;

public abstract class DirectAccessTest {

  private final long SERVICE_CONNECTION_TIME_OUT = 3000;
  private Object serviceMutex = new Object();
  private boolean connected = false;
  private Timer connectionTimer;
  private ServiceConnectionTimerTask mTimerTask = new ServiceConnectionTimerTask();
  private SEService mSEService;
  protected DirectAccessTransport mTransport;
  protected MDocStore mDocStore;
  protected String mDocName;
  protected StorageEngine mStorageEngine;
  protected Context mContext;

  protected ArrayList<KeyPair> mReaderKeys;
  protected HashMap<KeyPair, ArrayList<X509Certificate>> mReaderCertChain;

  private final OnConnectedListener mListener = new OnConnectedListener() {
    public void onConnected() {
      synchronized (serviceMutex) {
        connected = true;
        serviceMutex.notify();
      }
    }
  };

  class SynchronousExecutor implements Executor {

    public void execute(Runnable r) {
      r.run();
    }
  }

  class ServiceConnectionTimerTask extends TimerTask {

    @Override
    public void run() {
      synchronized (serviceMutex) {
        serviceMutex.notifyAll();
      }
    }
  }

  protected void waitForConnection() throws TimeoutException {
    if (mTransport instanceof DirectAccessSocketTransport) {
      return;
    }
    synchronized (serviceMutex) {
      if (!connected) {
        try {
          serviceMutex.wait();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      if (!connected) {
        throw new TimeoutException(
            "Service could not be connected after " + SERVICE_CONNECTION_TIME_OUT + " ms");
      }
      if (connectionTimer != null) {
        connectionTimer.cancel();
      }
    }
  }


  protected DirectAccessTransport getDirectAccessTransport(boolean useSocketTransport) {
    if (useSocketTransport) {
      return new DirectAccessSocketTransport();
    } else {
      return new DirectAccessOmapiTransport(mSEService);
    }
  }


  protected void init() {
    mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
    mSEService = new SEService(mContext, new SynchronousExecutor(), mListener);
    File storageDir = new File(mContext.getDataDir(), "ic-testing");
    mStorageEngine = new AndroidStorageEngine.Builder(mContext, storageDir).build();
    connectionTimer = new Timer();
    connectionTimer.schedule(mTimerTask, SERVICE_CONNECTION_TIME_OUT);
    mTransport = getDirectAccessTransport(true);
  }

  protected void reset() {
    if (mDocStore != null) {
      mDocStore.deleteCredential(mDocName);
      mDocStore = null;
    }
    try {
      if (mTransport != null) {
        mTransport.closeConnection();
        mTransport = null;
      }
    } catch (IOException e) {
      fail("Unexpected Exception " + e);
    }
  }

  protected void provisionAndSwapIn() {
    mDocName = "mDL";
    try {
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      mDocStore = new MDocStore(mTransport, mStorageEngine);
      MDocCredential credential = mDocStore.createCredential(mDocName,
          CredentialDataParser.MDL_DOC_TYPE, challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
      List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
          Duration.ofDays(180));
      Assert.assertEquals(numSigningKeys, certificationRequests.size());
      // Provision
      ArrayList<X509Certificate> cert = null;
      if (mReaderCertChain != null) {
        cert = new ArrayList<>();
        for(Map.Entry<KeyPair, ArrayList<X509Certificate>> entry : mReaderCertChain.entrySet()) {
          KeyPair key = entry.getKey();
          ArrayList<X509Certificate> certChain = entry.getValue();
          if (certChain != null && certChain.size() > 0) {
            cert.add(certChain.get(0)); // Add leaf public key
          }
        }
      }
      byte[] encodedCredData = DirectAccessTestUtils.createCredentialData(mContext,
          certificationRequests.get(0), CredentialDataParser.MDL_DOC_TYPE, cert);
      Logger.dCbor("DirectAccessTest", "encodedCredData Hardcoded", encodedCredData);
      print(encodedCredData);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      // Set data
      credential.swapIn(certificationRequests.get(0));
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }


  // public static void print(byte[] data) {
  //   int NO_CHARS_IN_LINE = 1024;
  //   int noCounts = data.length / NO_CHARS_IN_LINE;
  //   int remaining = data.length % NO_CHARS_IN_LINE;
  //   int i = 0;
  //   for (; i < noCounts; i++) {
  //     String str = tohexStr(data, (NO_CHARS_IN_LINE * i), NO_CHARS_IN_LINE);
  //     Log.d("<======>[" + i + "]", str);
  //   }
  //   String str = tohexStr(data, (i * NO_CHARS_IN_LINE), remaining);
  //   Log.d("<======>[" + i + "]", str);
  // }
  //
  // public static String tohexStr(byte[] data, int off, int len) {
  //   StringBuilder sb = new StringBuilder();
  //   System.out.println("----");
  //   for (int i = off; i < (off + len); i++) {
  //     sb.append(String.format("%02X", data[i]));
  //   }
  //   return sb.toString();
  // }
}
