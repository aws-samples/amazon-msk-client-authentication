package com.amazonaws.msk.samples;

import com.amazonaws.auth.*;
import com.amazonaws.services.acmpca.AWSACMPCA;
import java.security.cert.*;
import com.beust.jcommander.ParameterException;
import sun.security.tools.keytool.CertAndKeyGen;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AuthMSK {

    private static final Logger logger = LogManager.getLogger(AuthMSK.class);

    @Parameter(names={"--region", "-reg"})
    private String region = "us-east-1";
    private String endpointProtocol = "acm-pca." + region + ".amazonaws.com";

    @Parameter(names = {"--help", "-h"}, help = true)
    private boolean help = false;

    @Parameter(names={"--keystoreLocation", "-ksl"})
    private String keystoreLocation = "/tmp/kafka.client.keystore.jks";

    @Parameter(names={"--certificateAuthorityArn", "-caa"}, required = true)
    private String certificateAuthorityArn;

    @Parameter(names={"--alias", "-ksa"})
    private String alias = "msk";

    @Parameter(names={"--keystoreType", "-kst"})
    private String keystoreType = "PKCS12";

    @Parameter(names={"--keystorePassword", "-ksp"}, required = true)
    private String keystorePassword = "PKCS12";

    @Parameter(names={"--certificateArn", "-cfa"})
    private String certificateArn;

    @Parameter(names={"--getClientCertificate", "-gcc"})
    private boolean getClientCertificate;

    @Parameter(names={"--createPEMFiles", "-pem"})
    private boolean createPEMFiles;

    @Parameter(names={"--certificateValidity", "-cfv"})
    private long certificateValidity = 300L;

    @Parameter(names={"--privateKeyPEMFileLocation", "-pkf"})
    private String privateKeyPEMFileLocation = "/tmp/private_key.pem";

    @Parameter(names={"--clientCertFileLocation", "-ccf"})
    private String clientCertFileLocation = "/tmp/client_cert.pem";

    @Parameter(names={"--crossAccountRoleArn", "-cra"})
    private String crossAccountRoleArn;

    public static void main(String[] args) throws Exception{


        AuthMSK authMSK = new AuthMSK();
        JCommander jc = JCommander.newBuilder()
                .addObject(authMSK)
                .build();
        jc.parse(args);
        if (authMSK.help){
            jc.usage();
            return;
        }

        AWSACMPCA client;
        AWSACMPCAProxy awsacmpcaProxy = new AWSACMPCAProxy();
        Crypto crypto = new Crypto();

        logger.info("Getting AWS credentials");
        com.amazonaws.msk.samples.Credentials creds = new com.amazonaws.msk.samples.Credentials();
        AWSCredentials credentials = creds.getAWSCredentials();
        if (authMSK.crossAccountRoleArn != null) {
            logger.info("Getting cross account AWS credentials");
            BasicSessionCredentials crossAccountCredentials = creds.crossAccountAssumeRole(new AWSStaticCredentialsProvider(credentials), authMSK.region, authMSK.crossAccountRoleArn);
            logger.info("Setting up AWS ACM PCA client");
            client = new AWSACMPCAProxy().getAWSACMPCAClient(new AWSStaticCredentialsProvider(crossAccountCredentials), authMSK.region);
        } else {
            logger.info("Setting up AWS ACM PCA client");
            client = new AWSACMPCAProxy().getAWSACMPCAClient(new AWSStaticCredentialsProvider(credentials), authMSK.region);
        }

        if (!authMSK.getClientCertificate){

            if (authMSK.certificateArn != null){
                logger.info("Certificate Arn provided without the parameter --getClientCertificate(or -gcc). It will be ignored and a new certificate issued from ACM PCA.");
            }

            logger.info("Generating private key and certificate");
            CertAndKeyGen gen = crypto.generateKeyPairAndCert();
            crypto.createKeyStoreIfMissing(authMSK.keystoreType, authMSK.keystorePassword, authMSK.keystoreLocation);
            if (authMSK.createPEMFiles){
                logger.info(String.format("Writing out private key to: %s\n", authMSK.privateKeyPEMFileLocation));
                Util.writePEMFile(authMSK.privateKeyPEMFileLocation, crypto.getPrivateKeyinPEMFormat(gen));
            }

            X509Certificate [] privateKeyCertificateChain = crypto.generateKeyCertificateChain(gen, authMSK.certificateValidity);
            logger.info(String.format("Storing key and certificate in keystore: %s with alias: %s\n", authMSK.keystoreLocation, authMSK.alias));
            crypto.storeKeystoreKeyEntry(privateKeyCertificateChain, authMSK.alias, authMSK.keystorePassword, authMSK.keystoreType, gen.getPrivateKey(), authMSK.keystoreLocation);
            logger.info("Generating Certificate Signing Request");
            String csrReq = crypto.generateCSR(gen);
            logger.info(String.format("CSR generated: \n%s\n", csrReq));
            logger.info("Getting certificate issued from ACM PCA");
            authMSK.certificateArn = awsacmpcaProxy.issueCertificate(authMSK.certificateAuthorityArn, csrReq, client, authMSK.certificateValidity);

        } else {
            if (authMSK.certificateArn == null){
                throw new ParameterException(
                        "Certificate Arn parameter (--certificateArn or -ca) needs to be specified.");
            }
        }

        logger.info(String.format("Getting Certificate with Arn: %s\n from Certificate Authority with Arn: %s\n", authMSK.certificateArn, authMSK.certificateAuthorityArn));
        String certChain = awsacmpcaProxy.getCertificate(authMSK.certificateArn, authMSK.certificateAuthorityArn, client);
        logger.info(String.format("Retrieved certificate chain: \n%s\n ", certChain));

        if (authMSK.createPEMFiles){
            logger.info(String.format("Writing out signed client certificate to: %s\n", authMSK.clientCertFileLocation));
            Util.writePEMFile(authMSK.clientCertFileLocation, awsacmpcaProxy.getClientCertificate(authMSK.certificateArn, authMSK.certificateAuthorityArn, client).getBytes());
        }

        logger.info("Converting into X509 certificate chain");
        X509Certificate [] certificateChain = crypto.getCertChain(certChain);
        logger.info(String.format("Storing certificate in keystore: %s\n", authMSK.keystoreLocation));
        crypto.storeKeystoreKeyEntry(certificateChain, authMSK.alias, authMSK.keystorePassword, authMSK.keystoreType, null, authMSK.keystoreLocation);
    }
}
