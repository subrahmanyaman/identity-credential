package com.android.identity.wallet.document

import android.content.Context
import android.se.omapi.SEService
import com.android.identity.android.direct_access.DirectAccessCredential
import com.android.identity.android.direct_access.DirectAccessOmapiTransport
import com.android.identity.wallet.HolderApp
import java.util.concurrent.Executor




class OmapiTransport {
  private val mSyncExecutor =
    Executor { runnable: Runnable -> runnable.run() }
  private var daOmapiTransport: DirectAccessOmapiTransport? = null

  private constructor(context: Context, callback: HolderApp.SEListener) {
    daOmapiTransport = DirectAccessOmapiTransport(SEService(context, mSyncExecutor,
                                                            { callback.onConnected()}),
                                                  DirectAccessCredential.DIRECT_ACCESS_PROVISIONING_APPLET_ID)
  }

  fun getDirectAccessOmapiTransport() : DirectAccessOmapiTransport{
    return daOmapiTransport!!
  }

  companion object {
    @Volatile
    private var mOmapiTransport: OmapiTransport? = null
    fun instance(context: Context, callback: HolderApp.SEListener) : OmapiTransport {
      if (mOmapiTransport == null) {
        synchronized(OmapiTransport) {
          if (mOmapiTransport == null) {
            // Log.i("OmapiTransport", "fun instance")
            mOmapiTransport = OmapiTransport(context, callback)//instance(context, callback)
          }
        }
      }
      return mOmapiTransport!!
    }
  }
}
