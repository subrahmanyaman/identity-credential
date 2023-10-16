package com.android.identity.android.direct_access;

import android.se.omapi.SEService;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.android.identity.android.mdoc.transport.DataTransport;
import com.android.identity.credential.Credential;
import com.android.identity.storage.StorageEngine;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.Duration;

public class MDocStore {

  private final StorageEngine mStorageEngine;
  //private final SEService mSEService;
  private final  DirectAccessTransport mTransport;
  private static final boolean TEST = true;

  public MDocStore(@NonNull DirectAccessTransport transport,
      @NonNull StorageEngine storageEngine) throws IOException {
    this.mStorageEngine = storageEngine;
    this.mTransport = transport;
    // open the connection.
    mTransport.openConnection();
  }

  // Creates a new MDOC credential with the given name and DocType.
  //
  // The challenge must not be longer than XX bytes.
  //
  // Throws Doctype AlreadyExists if a credential with the given DocType
  // already exists for Direct Access.
  //
  // Throws MaxNumberOfCredentialsReached if there is not enough room in
  // Secure Hardware.
  //
  public MDocCredential createCredential(
      String name,
      String docType,
      byte[] challenge,
      int numSigningKeys,
      Duration signingKeyMinValidDuration) throws IOException, CertificateException {
    return MDocCredential.create(name, docType, challenge, numSigningKeys, signingKeyMinValidDuration,
        mStorageEngine, mTransport);
  }

  // Looks up a MDOC credential previously created with createMDocCredential().
  //
  // Returns `null` if no such credential exists.
  //
  @Nullable
  MDocCredential lookupCredential(String name) {
    return MDocCredential.lookupCredential(name, mStorageEngine, mTransport);
  }

  // Gets the maximum size of credentialData which can be used for credentials.
  // This is guaranteed to be at least 32 KiB.
  //
  // Applications can communicate this value to the issuer to ensure that the
  // data they provision will fit in Secure Hardware.
  //
  long getMaximumCredentialDataSize() {
    return 0;
  }

  public void deleteCredential(@NonNull String name) {
    MDocCredential credential = MDocCredential.lookupCredential(name, mStorageEngine, mTransport);
    if (credential == null) {
      return;
    }
    credential.deleteCredential();
  }
}
