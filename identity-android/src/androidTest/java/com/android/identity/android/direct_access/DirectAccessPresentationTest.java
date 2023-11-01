package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.identity.android.mdoc.deviceretrieval.IsoDepWrapper;
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper;
import com.android.identity.android.mdoc.transport.DataTransportOptions;
import com.android.identity.mdoc.connectionmethod.ConnectionMethod;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
//@RunWith(RobolectricTestRunner.class)
public class DirectAccessPresentationTest extends DirectAccessTest {
  private static final String TAG = "DirectAccessPresentationTest";
  private static final int DEVICE_ENGAGEMENT_RECEIVED = 1;
  private static final int ERROR = 2;
  private static final int DISCONNECTED = 3;
  private static final int DEVICE_RESPONSE_RECEIVED = 4;
  private CountDownLatch mCountDownLatch;
  private VerificationHelper mVerificationHelper;
  private List<ConnectionMethod> mConnectionMethods;
  private Throwable mError;

  private byte[] mDeviceResponse;

  static final String ISO_18013_5_ANNEX_D_DEVICE_REQUEST =
      "a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d"
          + "8185893a267646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d6553"
          + "7061636573a1716f72672e69736f2e31383031332e352e31a66b66616d696c795f6e616d65f56f646"
          + "f63756d656e745f6e756d626572f57264726976696e675f70726976696c65676573f56a6973737565"
          + "5f64617465f56b6578706972795f64617465f568706f727472616974f46a726561646572417574688"
          + "443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba175dc9"
          + "45755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f7"
          + "4301e170d3230313030313030303030305a170d3233313233313030303030305a3011310f300d0603"
          + "5504030c067265616465723059301306072a8648ce3d020106082a8648ce3d03010703420004f8912"
          + "ee0f912b6be683ba2fa0121b2630e601b2b628dff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135"
          + "177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185301c0603551d1f041530133011a"
          + "00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f30b464fada20b"
          + "fcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e3"
          + "00e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a"
          + "06082a8648ce3d0403020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec"
          + "4aae4e307206f9214930221009b94f0d739dfa84cca29efed529dd4838acfd8b6bee212dc6320c46f"
          + "eb839a35f658401f3400069063c189138bdcd2f631427c589424113fc9ec26cebcacacfcdb9695d28"
          + "e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf";

  public static
  byte[] fromHex( String stringWithHex) {
    int stringLength = stringWithHex.length();
    if ((stringLength % 2) != 0) {
      throw new IllegalArgumentException("Invalid length of hex string: " + stringLength);
    }
    int numBytes = stringLength / 2;
    byte[] data = new byte[numBytes];
    for (int n = 0; n < numBytes; n++) {
      String byteStr = stringWithHex.substring(2 * n, 2 * n + 2);
      data[n] = (byte) Integer.parseInt(byteStr, 16);
    }
    return data;
  }
  @Override
  @Before
  public void init() {
    super.init();
    mConnectionMethods = null;
    mError = null;
    mCountDownLatch = new CountDownLatch(1);
  }

  @Override
  @After
  public void reset() {
    Log.d(TAG, "Calling reset!!!!!");
    super.reset();
  }

  VerificationHelper.Listener mResponseListener = new VerificationHelper.Listener() {

    @Override
    public void onReaderEngagementReady(@NonNull byte[] readerEngagement) {
      Log.d(TAG, "onReaderEngagementReady");
      Log.d(TAG, "Thread id:"+Thread.currentThread().getId());
    }

    @Override
    public void onDeviceEngagementReceived(@NonNull List<ConnectionMethod> connectionMethods) {
      Log.d(TAG, "onDeviceEngagementReceived");
      Log.d(TAG, "Thread id:"+Thread.currentThread().getId());
      mConnectionMethods = ConnectionMethod.disambiguate(connectionMethods);
      Message msg = Message.obtain();
      msg.what = DEVICE_ENGAGEMENT_RECEIVED;
      mHandler.sendMessage(msg);
    }

    @Override
    public void onMoveIntoNfcField() {
      Log.d(TAG, "onMoveIntoNfcField");
    }

    @Override
    public void onDeviceConnected() {
      Log.d(TAG, "onDeviceConnected");
    }

    @Override
    public void onDeviceDisconnected(boolean transportSpecificTermination) {
      Log.d(TAG, "onDeviceDisconnected");
      Message msg = Message.obtain();
      msg.what = DISCONNECTED;
      mHandler.sendMessage(msg);
    }

    @Override
    public void onResponseReceived(@NonNull byte[] deviceResponseBytes) {
      Log.d(TAG, "onResponseReceived");
      mDeviceResponse = deviceResponseBytes;
      Message msg = Message.obtain();
      msg.what = DEVICE_RESPONSE_RECEIVED;
      mHandler.sendMessage(msg);
    }

    @Override
    public void onError(@NonNull Throwable error) {
      Log.d(TAG, "onError");
      Log.d(TAG, "Thread id:"+Thread.currentThread().getId());
      Message msg = Message.obtain();
      msg.what = ERROR;
      Bundle bundle = new Bundle();
      bundle.putString("Error", error.getMessage());
      mHandler.sendMessage(msg);
    }
  };

  public static IsoDep mIsoDep;
  Handler mHandler;
  final Handler.Callback cb = new Handler.Callback() {
    public boolean handleMessage(Message msg) {
      Log.d(TAG, "Handler Thread id:"+Thread.currentThread().getId());
      switch (msg.what) {
        case DEVICE_ENGAGEMENT_RECEIVED:
          Assert.assertNotNull(mConnectionMethods);
          Assert.assertTrue(mConnectionMethods.size() > 0);
          mVerificationHelper.connect(mConnectionMethods.get(0));
          byte[] devReq = fromHex(ISO_18013_5_ANNEX_D_DEVICE_REQUEST);
          // send device request
          mVerificationHelper.sendRequest(devReq);
          return true;
        case ERROR:
          Bundle bundle = msg.getData();
          fail(bundle.getString("Error"));
          mCountDownLatch.countDown();
          return true;
        case DEVICE_RESPONSE_RECEIVED:
          // TODO Validate the response.
          Assert.assertNotNull(mDeviceResponse);
          mCountDownLatch.countDown();
          return true;
        case DISCONNECTED:
          mCountDownLatch.countDown();
          return true;
      }
      return false;
    }
  };

  @Test
  public void testPresentation() {
    try {
      provisionAndSwapIn();
      Log.d(TAG, "Thread id:" + Thread.currentThread().getId());
      Executor executor = Executors.newSingleThreadExecutor();
      mHandler = new Handler(mContext.getMainLooper(), cb);
      VerificationHelper.Builder builder = new VerificationHelper.Builder(mContext,
          mResponseListener,
          executor);
      DataTransportOptions options = new DataTransportOptions.Builder().setBleClearCache(false)
          .setBleClearCache(false).build();
      builder.setDataTransportOptions(options);
      mVerificationHelper = builder.build();

      IsoDepWrapper wrapper = new ShadowIsoDep(mTransport);
      mVerificationHelper.mockTagDiscovered(wrapper);
      try {
        mCountDownLatch.await();
      } catch (InterruptedException e) {
        fail(e.getMessage());
      }
    } finally {
      reset();
    }

  }


}
