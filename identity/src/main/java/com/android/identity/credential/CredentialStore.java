/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity.credential;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.identity.securearea.SecureArea;
import com.android.identity.securearea.SecureAreaRepository;
import com.android.identity.storage.StorageEngine;

import java.util.ArrayList;
import java.util.List;

/**
 * Class for holding real-world identity credentials.
 *
 * <p>This class is designed for storing real-world identity credentials such as
 * Mobile Driving Licenses (mDL) as specified in ISO/IEC 18013-5:2021. It is however
 * not tied to that specific credential shape and is designed to hold any kind of
 * credential, regardless of shape, presentation-, or issuance-protocol used.
 *
 * <p>This code relies on a Secure Area for keys and this dependency is abstracted
 * by the {@link SecureArea} interface and allows the use of different implementations
 * on a per-credential basis. Persistent storage of credentials is abstracted via
 * the {@link StorageEngine} interface which provides a simple key/value store.
 *
 * <p>For more details about credentials stored in a {@link CredentialStore} see the
 * {@link Credential} class.
 */
public class CredentialStore {
    private final StorageEngine mStorageEngine;
    private final SecureAreaRepository mSecureAreaRepository;

    /**
     * Creates a new credential store.
     *
     * @param storageEngine the {@link StorageEngine} to use for storing/retrieving credentials.
     * @param secureAreaRepository the repository of configured {@link SecureArea} that can
     *                                 be used.
     */
    public CredentialStore(@NonNull StorageEngine storageEngine,
                           @NonNull SecureAreaRepository secureAreaRepository) {
        mStorageEngine = storageEngine;
        mSecureAreaRepository = secureAreaRepository;
    }

    /**
     * Creates a new credential.
     *
     * <p>If a credential with the given name already exists, it will be overwritten by the
     * newly created credential.
     *
     * @param name name of the credential.
     * @param credentialKeySettings the settings to use for CredentialKey.
     * @return A newly created credential.
     */
    public @NonNull Credential createCredential(@NonNull String name,
                                                @NonNull SecureArea.CreateKeySettings credentialKeySettings) {
        return Credential.create(mStorageEngine,
                mSecureAreaRepository,
                name,
                credentialKeySettings);
    }

    /**
     * Looks up a previously created credential.
     *
     * @param name the name of the credential.
     * @return the credential or {@code null} if not found.
     */
    public @Nullable Credential lookupCredential(@NonNull String name) {
        return Credential.lookup(mStorageEngine, mSecureAreaRepository, name);
    }

    /**
     * Lists all credentials in the store.
     *
     * @return list of all credential names in the store.
     */
    public @NonNull List<String> listCredentials() {
        ArrayList<String> ret = new ArrayList<>();
        for (String name : mStorageEngine.enumerate()) {
            if (name.startsWith(Credential.CREDENTIAL_PREFIX)) {
                ret.add(name.substring(Credential.CREDENTIAL_PREFIX.length()));
            }
        }
        return ret;
    }

    /**
     * Deletes a credential.
     *
     * <p>If the credential doesn't exist this does nothing.
     *
     * @param name the name of the credential.
     */
    public void deleteCredential(@NonNull String name) {
        Credential credential = lookupCredential(name);
        if (credential == null) {
            return;
        }
        credential.deleteCredential();
    }
}
