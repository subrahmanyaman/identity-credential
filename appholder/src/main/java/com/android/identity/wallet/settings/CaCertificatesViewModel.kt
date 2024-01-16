package com.android.identity.wallet.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.android.identity.wallet.HolderApp
import com.android.identity.wallet.trustmanagement.getSubjectKeyIdentifier
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

class CaCertificatesViewModel() : ViewModel() {

    private val _screenState = MutableStateFlow(CaCertificatesScreenState())
    val screenState: StateFlow<CaCertificatesScreenState> = _screenState.asStateFlow()

    private val _currentCertificateItem = MutableStateFlow<CertificateItem?>(null)
    val currentCertificateItem = _currentCertificateItem.asStateFlow()
    fun loadCertificates() {
        val certificates =
            HolderApp.trustManagerInstance.getAllTrustPoints().map { it.toCertificateItem() }
        _screenState.update { it.copy(certificates = certificates) }
    }

    fun setCurrentCertificateItem(certificateItem: CertificateItem) {
        _currentCertificateItem.update { certificateItem }
    }

    fun deleteCertificate() {
        _currentCertificateItem.value?.trustPoint?.let {
            HolderApp.trustManagerInstance.removeTrustPoint(it)
            HolderApp.certificateStorageEngineInstance.delete(it.certificate.getSubjectKeyIdentifier())
        }
    }

    companion object {
        fun factory(): ViewModelProvider.Factory {
            return viewModelFactory {
                initializer { CaCertificatesViewModel() }
            }
        }
    }
}