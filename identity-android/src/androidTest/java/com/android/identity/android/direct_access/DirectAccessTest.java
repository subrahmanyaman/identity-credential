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
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;

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
    }
    try {
      if (mTransport != null) {
        mTransport.closeConnection();
      }
    } catch (IOException e) {
      fail("Unexpected Exception " + e);
    }

  }

}
