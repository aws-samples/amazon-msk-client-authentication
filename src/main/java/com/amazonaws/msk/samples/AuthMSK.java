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

    @Parameter(names={"--region", "-reg"}, description = "AWS Region.")
    private String region = "us-east-1";
    private String endpointProtocol = "acm-pca." + region + ".amazonaws.com";

    @Parameter(names = {"--help", "-h"}, help = true)
    private boolean help = false;

    @Parameter(names={"--keystoreLocation", "-ksl"}, description = "The location of the keystore file.")
    private String keystoreLocation = "/tmp/kafka.client.keystore.jks";

    @Parameter(names={"--certificateAuthorityArn", "-caa"}, required = true, description = "The Arn of the Private Certificate Authority in ACM to issue the end-client certificates.")
    private String certificateAuthorityArn;

    @Parameter(names={"--alias", "-ksa"}, description = "The alias of the key entry in the keystore.")
    private String alias = "msk";

    @Parameter(names={"--keystoreType", "-kst"}, description = "The keystore type.")
    private String keystoreType = "PKCS12";

    @Parameter(names={"--keystorePassword", "-ksp"}, required = true, description = "The keystore password.")
    private String keystorePassword;

    @Parameter(names={"--certificateArn", "-cfa"}, description = "Specified Arn of the ACM PCA certificate that needs to be retrieved and installed. Needs to be specified if -gcc is specified. Works in conjunction with -gcc flag. Has no effect if the -gcc flag is not specified.")
    private String certificateArn;

    @Parameter(names={"--getClientCertificate", "-gcc"}, description = "Optional flag denoting that the Private Key generation and certificate issuance can be skipped and the certificate specified with the -cfa parameter should be retrieved and installed in the keystore. This can help with the renewal of certificates when ACM is authorized to auto-renew the PCA certificates.")
    private boolean getClientCertificate;

    @Parameter(names={"--createPEMFiles", "-pem"}, description = "Optional flag to create PEM files for the Private Key and the issued client certificate to be used by clients in python, node.js etc.")
    private boolean createPEMFiles;

    @Parameter(names={"--certificateValidity", "-cfv"}, description = "The validity of the certificate to be issued in days.")
    private long certificateValidity = 300L;

    @Parameter(names={"--privateKeyPEMFileLocation", "-pkf"}, description = "Specifies the Private Key PEM file location. Works in conjunction with -pem flag. Has no effect if the -pem flag is not specified.")
    private String privateKeyPEMFileLocation = "/tmp/private_key.pem";

    @Parameter(names={"--clientCertFileLocation", "-ccf"}, description = "Specifies the Client Certificate PEM file location. Works in conjunction with -pem flag. Has no effect if the -pem flag is not specified.")
    private String clientCertFileLocation = "/tmp/client_cert.pem";

    @Parameter(names={"--crossAccountRoleArn", "-cra"}, description = "Optional parameter that specifies an IAM Role in the ACM PCA account to assume when the client is in a different account from the ACM PCA.")
    private String crossAccountRoleArn;

    @Parameter(names={"--distinguishedName", "-dgn"}, description = "The distinguished name of the certificate issued by the ACM PCA. (Default hostname)")
    private String distinguishedName;

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
            String csrReq = crypto.generateCSR(gen, authMSK.distinguishedName);
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
