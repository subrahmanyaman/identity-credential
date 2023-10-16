package com.android.identity.android.direct_access;

import java.security.cert.X509Certificate;
import java.util.List;

public class PresentationPackage {
  public List<X509Certificate> signingCert;
  public byte[] encryptedData;

}
