package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import android.content.Context;
import android.se.omapi.SEService;
import android.se.omapi.SEService.OnConnectedListener;
import androidx.test.platform.app.InstrumentationRegistry;
import com.android.identity.android.storage.AndroidStorageEngine;
import com.android.identity.storage.StorageEngine;
import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
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
  //MDocStore mDocStore;
  //String mDocName;
  protected StorageEngine mStorageEngine;
  Context mContext;
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
          DirectAccessTestUtils.MDL_DOCTYPE, challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
      List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
          Duration.ofDays(180));
      Assert.assertEquals(numSigningKeys, certificationRequests.size());
      // Provision
      byte[] encodedCredData = DirectAccessTestUtils.createCredentialData(mContext,
          certificationRequests.get(0), DirectAccessTestUtils.MDL_DOCTYPE);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      // TODO Swap-in flow not tested.
      credential.swapIn(certificationRequests.get(0));
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

}
