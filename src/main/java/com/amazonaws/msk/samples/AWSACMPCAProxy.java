package com.amazonaws.msk.samples;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder;
import com.amazonaws.services.acmpca.model.*;
import com.amazonaws.waiters.Waiter;
import com.amazonaws.waiters.WaiterParameters;
import com.amazonaws.waiters.WaiterTimedOutException;
import com.amazonaws.waiters.WaiterUnrecoverableException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

class AWSACMPCAProxy {

    private static final Logger logger = LogManager.getLogger(AuthMSK.class);


    AWSACMPCA getAWSACMPCAClient(AWSStaticCredentialsProvider credentials, String region){
        // Create a client that you can use to make requests.
        return AWSACMPCAClientBuilder.standard()
                .withRegion(region)
                .withCredentials(credentials)
                .build();
    }

    String issueCertificate(String certificateAuthorityArn, String csr, AWSACMPCA client, Long certificateValidity){

        // Create a certificate request:
        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest();
        issueCertificateRequest.withCertificateAuthorityArn(certificateAuthorityArn)
                .withCsr(Util.stringToByteBuffer(csr))
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withValidity(new Validity().withType(ValidityPeriodType.DAYS)
                        .withValue(certificateValidity))
                .withIdempotencyToken("1234");

        IssueCertificateResult issueCertificateResult;

        issueCertificateResult = client.issueCertificate(issueCertificateRequest);
        logger.info("Certificate Arn: " + issueCertificateResult.getCertificateArn());
        return issueCertificateResult.getCertificateArn();

    }

    String getCertificate(String certificateArn, String certificateAuthorityArn, AWSACMPCA client) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        getCertificateRequest.withCertificateArn(certificateArn)
                .withCertificateAuthorityArn(certificateAuthorityArn);

        // Create waiter to wait on successful creation of the certificate file.
        Waiter<GetCertificateRequest> waiter = client.waiters().certificateIssued();
        try {
            waiter.run(new WaiterParameters<>(getCertificateRequest));
        } catch(WaiterUnrecoverableException | WaiterTimedOutException e) {
            //Explicit short circuit when the recourse transitions into
            //an undesired state.
            logger.error("Error getting client certificate chain.\n");
            throw e;
        } //Failed to transition into desired state even after polling.

        GetCertificateResult getCertificateResult;

        getCertificateResult = client.getCertificate(getCertificateRequest);
        return (getCertificateResult.getCertificate() + "\n" + getCertificateResult.getCertificateChain());
    }

    String getClientCertificate(String certificateArn, String certificateAuthorityArn, AWSACMPCA client) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        getCertificateRequest.withCertificateArn(certificateArn)
                .withCertificateAuthorityArn(certificateAuthorityArn);

        // Create waiter to wait on successful creation of the certificate file.
        Waiter<GetCertificateRequest> waiter = client.waiters().certificateIssued();
        try {
            waiter.run(new WaiterParameters<>(getCertificateRequest));
        } catch(WaiterUnrecoverableException | WaiterTimedOutException e) {
            //Explicit short circuit when the recourse transitions into
            //an undesired state.
            logger.error("Error getting client certificate.\n");
            throw e;
        } //Failed to transition into desired state even after polling.

        GetCertificateResult getCertificateResult;

        getCertificateResult = client.getCertificate(getCertificateRequest);
        return getCertificateResult.getCertificate();
    }
}
