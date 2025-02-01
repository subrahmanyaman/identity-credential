package com.android.identity.testapp

import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.Composable
import androidx.compose.ui.tooling.preview.Preview
import androidx.fragment.app.FragmentActivity
import com.android.identity.util.AndroidContexts
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class MainActivity : FragmentActivity() {

    companion object {
        private const val TAG = "MainActivity"

        private var bcInitialized = false

        fun initBouncyCastle() {
            if (bcInitialized) {
                return
            }
            // This is needed to prefer BouncyCastle bundled with the app instead of the Conscrypt
            // based implementation included in the OS itself.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())
            bcInitialized = true
        }

        init {
            initBouncyCastle()
        }
    }

    private val app = App()

    override fun onResume() {
        super.onResume()
        AndroidContexts.setCurrentActivity(this)
        NfcAdapter.getDefaultAdapter(this)?.let {
            CardEmulation.getInstance(it)?.setPreferredService(this, ComponentName(this, NdefService::class::class.java))
        }
    }

    override fun onPause() {
        super.onPause()
        AndroidContexts.setCurrentActivity(null)
        NfcAdapter.getDefaultAdapter(this)?.let {
            CardEmulation.getInstance(it)?.unsetPreferredService(this)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        initBouncyCastle()

        CoroutineScope(Dispatchers.Main).launch {
            app.init()
            setContent {
                app.Content()
            }
        }
    }
}

private val previewApp: App by lazy { App() }

@Preview
@Composable
fun AppAndroidPreview() {
    previewApp.Content()
}