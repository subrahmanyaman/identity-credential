package com.android.identity.wallet.fragment

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.android.identity.mdoc.origininfo.OriginInfo
import com.android.identity.wallet.databinding.FragmentReverseEngagementBinding
import com.android.identity.wallet.util.log
import com.android.identity.wallet.util.logWarning
import com.android.identity.wallet.viewmodel.ShareDocumentViewModel
import com.budiyev.android.codescanner.CodeScanner
import com.budiyev.android.codescanner.DecodeCallback

class ReverseEngagementFragment : Fragment() {

    private var _binding: FragmentReverseEngagementBinding? = null
    private var codeScanner: CodeScanner? = null

    private val binding get() = _binding!!
    private val vm: ShareDocumentViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentReverseEngagementBinding.inflate(inflater)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        binding.btCancel.setOnClickListener {
            findNavController().navigate(
                ReverseEngagementFragmentDirections.actionReverseEngagementFragmentToSelectDocumentFragment()
            )
        }

        codeScanner = CodeScanner(requireContext(), binding.csScanner)
        codeScanner?.decodeCallback = DecodeCallback { result ->
            requireActivity().runOnUiThread {
                val qrText = result.text
                log("qrText: $qrText")
                val uri = Uri.parse(qrText)
                if (uri.scheme.equals("mdoc")) {
                    vm.startPresentationReverseEngagement(qrText, emptyList<OriginInfo>())
                    findNavController().navigate(
                        ReverseEngagementFragmentDirections.actionReverseEngagementFragmentToTransferDocumentFragment()
                    )
                } else {
                    logWarning("Ignoring QR code with scheme " + uri.scheme)
                }
            }
        }
        binding.csScanner.setOnClickListener { codeScanner?.startPreview() }
    }

    override fun onResume() {
        super.onResume()
        enableReader()
    }

    override fun onPause() {
        super.onPause()
        disableReader()
    }

    private fun enableReader() {
        if (isAllPermissionsGranted()) {
            codeScanner?.startPreview()
        } else {
            shouldRequestPermission()
        }
    }

    private fun disableReader() {
        codeScanner?.releaseResources()
    }

    private val appPermissions: List<String>
        get() = mutableListOf(Manifest.permission.CAMERA)

    private fun shouldRequestPermission() {
        val permissionsNeeded = appPermissions.filter { permission ->
            ContextCompat.checkSelfPermission(
                requireContext(),
                permission
            ) != PackageManager.PERMISSION_GRANTED
        }

        if (permissionsNeeded.isNotEmpty()) {
            permissionsLauncher.launch(
                permissionsNeeded.toTypedArray()
            )
        }
    }

    private fun isAllPermissionsGranted(): Boolean {
        // If any permission is not granted return false
        return appPermissions.none { permission ->
            ContextCompat.checkSelfPermission(
                requireContext(),
                permission
            ) != PackageManager.PERMISSION_GRANTED
        }
    }

    private val permissionsLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
            permissions.entries.forEach {
                log("permissionsLauncher ${it.key} = ${it.value}")
                // Open settings if user denied any required permission
                if (!it.value && !shouldShowRequestPermissionRationale(it.key)) {
                    openSettings()
                    return@registerForActivityResult
                }
            }
        }

    private fun openSettings() {
        val intent = Intent()
        intent.action = Settings.ACTION_APPLICATION_DETAILS_SETTINGS
        intent.data = Uri.fromParts("package", requireContext().packageName, null)
        startActivity(intent)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}