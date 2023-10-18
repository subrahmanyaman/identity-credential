package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import android.nfc.tech.IsoDep;
import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.identity.android.mdoc.deviceretrieval.IsoDepWrapper;
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper;
import com.android.identity.android.mdoc.transport.DataTransportOptions;
import com.android.identity.mdoc.connectionmethod.ConnectionMethod;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
//@RunWith(RobolectricTestRunner.class)
public class DirectAccessPresentationTest extends DirectAccessTest {

  @Override
  @Before
  public void init() {
    super.init();
  }

  @Override
  @After
  public void reset() {
    super.reset();
  }

  private VerificationHelper.Listener mResponseListener = new VerificationHelper.Listener() {


    @Override
    public void onReaderEngagementReady(@NonNull byte[] readerEngagement) {

    }

    @Override
    public void onDeviceEngagementReceived(@NonNull List<ConnectionMethod> connectionMethods) {

    }

    @Override
    public void onMoveIntoNfcField() {

    }

    @Override
    public void onDeviceConnected() {

    }

    @Override
    public void onDeviceDisconnected(boolean transportSpecificTermination) {

    }

    @Override
    public void onResponseReceived(@NonNull byte[] deviceResponseBytes) {

    }

    @Override
    public void onError(@NonNull Throwable error) {

    }
  };

  public static IsoDep mIsoDep;

  @Test
  public void testPresentation() {
    try {
      waitForConnection();
    } catch (TimeoutException e) {
      fail("Timeout Exception");
    }
    VerificationHelper.Builder builder = new VerificationHelper.Builder(mContext, mResponseListener,
        mContext.getMainExecutor());
    DataTransportOptions options = new DataTransportOptions.Builder().setBleClearCache(false)
        .setBleClearCache(false).build();
    builder.setDataTransportOptions(options);
    VerificationHelper verification = builder.build();

    IsoDepWrapper wrapper = new ShadowIsoDep(mTransport);
    verification.mockTagDiscovered(wrapper);


  }


}
