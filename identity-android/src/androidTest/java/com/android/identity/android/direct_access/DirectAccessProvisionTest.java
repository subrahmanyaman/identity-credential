package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.IOException;
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

  @Test
  public void createMDocStore() {

  }

  @Test
  public void provisionSuccess() {
    try {
      mDocName = "mDL";
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      mDocStore = new MDocStore(mTransport, mStorageEngine);
      MDocCredential credential = mDocStore.createCredential(mDocName,
          CredentialDataParser.MDL_DOC_TYPE, challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
      List<MDocCredential.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
          Duration.ofDays(180));
      Assert.assertEquals(numSigningKeys, certificationRequests.size());
      // Provision
      byte[] encodedCredData = DirectAccessTestUtils.createCredentialData(mContext,
          certificationRequests.get(0), CredentialDataParser.MDL_DOC_TYPE);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void createCredentialWithInvalidDocType() {
    String docName = "myDoc";
    String invalidDocType = "invalid-docType";
    MDocStore docStore = null;
    try {
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      docStore = new MDocStore(mTransport, mStorageEngine);
      docStore.createCredential(docName,
          invalidDocType, challenge, numSigningKeys, Duration.ofDays(365));
      fail();
    } catch (IllegalStateException expected)  {

    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void provisionInvalidCredentialData() {

  }

  @Test
  public void createCredentialWithLargeChallenge() {
  }

}
