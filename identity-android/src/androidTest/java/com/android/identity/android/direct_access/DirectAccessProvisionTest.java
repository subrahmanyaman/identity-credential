package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class DirectAccessProvisionTest extends DirectAccessTest {

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

  private MDocCredential createMDocCredential(String docName, String docType, byte[] challenge,
      int numSigningKeys, Duration duration) throws IOException, CertificateException {
    mDocStore = new MDocStore(mTransport, mStorageEngine);
    return mDocStore.createCredential(mDocName, CredentialDataParser.MDL_DOC_TYPE, challenge,
        numSigningKeys, Duration.ofDays(365));
  }

  @Test
  public void createMDocStore() {

  }

  @Test
  public void provisionSuccess() {
    try {
      waitForConnection();
      mDocName = "mDL";
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      MDocCredential credential = createMDocCredential(mDocName, CredentialDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
      List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
          Duration.ofDays(180));
      Assert.assertEquals(numSigningKeys, certificationRequests.size());
      // Provision
      byte[] encodedCredData = DirectAccessTestUtils.createCredentialData(mContext,
          certificationRequests.get(0), CredentialDataParser.MDL_DOC_TYPE, null);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void createCredentialWithInvalidDocTypeThrowsIllegalArgumentException() {
    try {
      waitForConnection();
      mDocName = "myDoc";
      String invalidDocType = "invalid-docType";
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      createMDocCredential(mDocName, invalidDocType, challenge, numSigningKeys,
          Duration.ofDays(365));
      fail("Expected to fail when invalid docType is passed.");
    } catch (IllegalArgumentException expected) {
      // Excepted exception.
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void provisionWithEmptyCredentialDataThrowsIllegalArgumentException() {
    MDocCredential credential = null;
    int numSigningKeys = 0;
    try {
      mDocName = "mDL";
      credential = null;
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      numSigningKeys = 1;
      credential = createMDocCredential(mDocName, CredentialDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }

    List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
        Duration.ofDays(180));
    Assert.assertEquals(numSigningKeys, certificationRequests.size());
    try {
      // Provision
      byte[] encodedCredData = {};
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      fail("Expected to fail when empty credential data is passed.");
    } catch (IllegalArgumentException e) {
      // Expected Exception
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void provisionWithInvalidCredentialDataThrowsIllegalArgumentException() {
    MDocCredential credential = null;
    int numSigningKeys = 0;
    try {
      mDocName = "mDL";
      credential = null;
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      numSigningKeys = 1;
      credential = createMDocCredential(mDocName, CredentialDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }

    List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
        Duration.ofDays(180));
    Assert.assertEquals(numSigningKeys, certificationRequests.size());
    try {
      // Provision
      // TODO loop through different types of invalid cbor data.
      byte[] encodedCredData = "invalid-cred-data".getBytes(StandardCharsets.UTF_8);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      fail("Expected to fail when empty credential data is passed.");
    } catch (IllegalArgumentException e) {
      // Expected Exception
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void lookupWithDifferentDocNameThrowsIllegalArgumentException() {
  }

  @Test
  public void createCredentialWithLargeChallenge() {
  }

}
