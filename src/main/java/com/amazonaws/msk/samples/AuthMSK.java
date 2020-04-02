package com.amazonaws.msk.samples;

import com.amazonaws.auth.*;
import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder;
import com.amazonaws.services.acmpca.model.*;
import java.io.*;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import com.amazonaws.AmazonClientException;
import com.amazonaws.services.acmpca.model.SigningAlgorithm;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;
import com.amazonaws.services.securitytoken.model.Credentials;
import com.amazonaws.waiters.Waiter;
import com.amazonaws.waiters.WaiterParameters;
import com.amazonaws.waiters.WaiterTimedOutException;
import com.amazonaws.waiters.WaiterUnrecoverableException;
import com.beust.jcommander.ParameterException;
import sun.security.pkcs10.PKCS10;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.xml.bind.DatatypeConverter;


public class AuthMSK {

    private static final Logger logger = LogManager.getLogger(AuthMSK.class);

    @Parameter(names={"--region", "-reg"})
    private String region = "us-east-1";
    private String endpointProtocol = "acm-pca." + region + ".amazonaws.com";

    @Parameter(names = {"--help", "-h"}, help = true)
    private boolean help = false;

    @Parameter(names={"--keystoreLocation", "-ksl"})
    private String keystoreLocation = "/home/ec2-user/kafka240/kafka.client.keystore.jks";

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
    private String privateKeyPEMFileLocation = "/home/ec2-user/kafka240/private_key.pem";

    @Parameter(names={"--clientCertFileLocation", "-ccf"})
    private String clientCertFileLocation = "/home/ec2-user/kafka240/client_cert.pem";

    @Parameter(names={"--crossAccountRoleArn", "-cra"})
    private String crossAccountRoleArn;

    private AWSCredentials getAWSCredentials(){
        AWSCredentials credentials;
        try {
            credentials =  new DefaultAWSCredentialsProviderChain().getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException(
                    "Cannot load the credentials using the DefaultAWSCredentialsProviderChain.",
                    e);
        }
        return credentials;
    }

    private BasicSessionCredentials crossAccountAssumeRole(AWSCredentialsProvider credentials){

        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                .withRegion(region)
                .withCredentials(credentials)
                .build();

        AssumeRoleRequest assumeRoleRequest = new AssumeRoleRequest();
        assumeRoleRequest.withDurationSeconds(3600)
                .withRoleArn(crossAccountRoleArn)
                .withRoleSessionName("AssumeRolePCA");

        AssumeRoleResult assumeRoleResult = stsClient.assumeRole(assumeRoleRequest);
        Credentials assumeRoleCredentials = assumeRoleResult.getCredentials();
        return new BasicSessionCredentials(assumeRoleCredentials.getAccessKeyId(), assumeRoleCredentials.getSecretAccessKey(), assumeRoleCredentials.getSessionToken());
    }

    private AWSACMPCA getAWSACMPCAClient(AWSStaticCredentialsProvider credentials){
        // Create a client that you can use to make requests.
        return AWSACMPCAClientBuilder.standard()
                .withRegion(region)
                .withCredentials(credentials)
                .build();

    }

    private void storeKeystoreKeyEntry(X509Certificate [] certificateChain, String alias, String password, String keystoreType, Key key) throws Exception {
        KeyStore keystore = KeyStore.getInstance(keystoreType);
        try {
            keystore.load(new FileInputStream(keystoreLocation), password.toCharArray());
        } catch (IOException e) {
            if (e.getMessage().equals("keystore password was incorrect"))
                logger.info(String.format("Found existing keystore at location: %s\n", keystoreLocation));
            throw e;
        }

        if (key != null){
            keystore.setKeyEntry(alias, key, password.toCharArray(), certificateChain);
        } else {

            key = keystore.getKey(alias, password.toCharArray());
            if (key == null) {
                throw new Exception(String.format("Unable to get key entry for alias %s. Did you provide the right alias?. Exiting..\n", alias));
            }
            keystore.setKeyEntry(alias, key, password.toCharArray(), certificateChain);

        }
        keystore.store(new FileOutputStream(keystoreLocation), password.toCharArray());
    }

    private CertAndKeyGen generateKeyPairAndCert() throws NoSuchAlgorithmException, InvalidKeyException {

            CertAndKeyGen gen = new CertAndKeyGen("RSA","SHA256WithRSA");
            gen.generate(2048);
            return gen;
    }

    private void createKeyStoreIfMissing(String keystoreType, String password) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

        KeyStore keystore = KeyStore.getInstance(keystoreType);
        try {
            logger.info("Checking for existing keystore.");
            keystore.load(new FileInputStream(keystoreLocation), password.toCharArray());
            logger.info(String.format("Existing keystore was found at location %s and loaded.", keystore));
        } catch (FileNotFoundException e) {
            logger.info("No existing keystore found. Creating new keystore.");
            keystore.load(null, null);
        } catch (IOException e) {
            if (e.getMessage().equals("keystore password was incorrect"))
                logger.info(String.format("Found existing keystore at location: %s\n", keystoreLocation));
            throw e;
        }
        keystore.store(new FileOutputStream(keystoreLocation), password.toCharArray());
    }

    private X509Certificate [] generateKeyCertificateChain(CertAndKeyGen gen) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {
        X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=" + InetAddress.getLocalHost().getHostName()), certificateValidity *24*3600);

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        return chain;
    }

    private byte [] getPrivateKeyinPEMFormat(CertAndKeyGen gen){

        String keypem  = "-----BEGIN RSA PRIVATE KEY-----\n" +
                DatatypeConverter.printBase64Binary(gen.getPrivateKey().getEncoded()) + "\n" +
                "\n-----END RSA PRIVATE KEY-----\n";
        logger.info(keypem);
        return keypem.getBytes();
    }

    private String generateCSR(CertAndKeyGen gen) throws IOException, InvalidKeyException, SignatureException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);

            X500Name x500Name = new X500Name("CN=" + InetAddress.getLocalHost().getHostName());
            PKCS10 pkcs10CSR = gen.getCertRequest(x500Name);
            pkcs10CSR.print(printStream);
        return outStream.toString().replace("BEGIN NEW CERTIFICATE REQUEST", "BEGIN CERTIFICATE REQUEST").replace("END NEW CERTIFICATE REQUEST", "END CERTIFICATE REQUEST");
    }

    private static ByteBuffer stringToByteBuffer(final String string) {
        if (Objects.isNull(string)) {
            return null;
        }
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.wrap(bytes);
    }

    private String issueCertificate(String certificateAuthorityArn, String csr, AWSACMPCA client){

        // Create a certificate request:
        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest();
        issueCertificateRequest.withCertificateAuthorityArn(certificateAuthorityArn)
                .withCsr(stringToByteBuffer(csr))
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withValidity(new Validity().withType(ValidityPeriodType.DAYS)
                                            .withValue(certificateValidity))
                .withIdempotencyToken("1234");

        IssueCertificateResult issueCertificateResult;

        issueCertificateResult = client.issueCertificate(issueCertificateRequest);
        logger.info("Certificate Arn: " + issueCertificateResult.getCertificateArn());
        return issueCertificateResult.getCertificateArn();

    }

    private String getCertificate(String certificateArn, String certificateAuthorityArn, AWSACMPCA client) {
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

    private String getClientCertificate(String certificateArn, String certificateAuthorityArn, AWSACMPCA client) {
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

    private X509Certificate [] getCertChain(String certChain) throws CertificateException {
        int fromIndex = 0;
        List<String> certs = new ArrayList<>();
        Integer addVal;

        while (certChain.indexOf("-----BEGIN CERTIFICATE-----\n", fromIndex) != -1) {
            int beginIndex = certChain.indexOf("-----BEGIN CERTIFICATE-----\n", fromIndex);
            Integer endIndex = certChain.indexOf("-----END CERTIFICATE-----\n", fromIndex);
            if (endIndex == -1) {
                endIndex = certChain.indexOf("-----END CERTIFICATE-----", fromIndex);
                addVal = "-----END CERTIFICATE-----".length();
            }
            else {
                addVal = "-----END CERTIFICATE-----\n".length();
            }

            certs.add(certChain.substring(beginIndex, endIndex + addVal));
            fromIndex = endIndex + addVal;

        }
        X509Certificate [] chain = new X509Certificate[certs.size()];
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        int i = 0;

        for (String cert: certs) {
            X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certs.get(i).getBytes()));
            x509Certificate.checkValidity();
            chain[i] = x509Certificate;
            i++;
        }

        return chain;
    }

    private void writePEMFile(String fileLocation, byte [] pem) throws IOException {
        try (FileOutputStream file = new FileOutputStream(fileLocation)) {
            file.write(pem);
        } catch (FileNotFoundException e) {
            logger.error(String.format("Nonexistent path %s provided for PEM file path. \n", fileLocation));
            throw e;
        }
    }

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

        logger.info("Getting AWS credentials");
        AWSCredentials credentials = authMSK.getAWSCredentials();
        if (authMSK.crossAccountRoleArn != null) {
            logger.info("Getting cross account AWS credentials");
            BasicSessionCredentials crossAccountCredentials = authMSK.crossAccountAssumeRole(new AWSStaticCredentialsProvider(credentials));
            logger.info("Setting up AWS ACM PCA client");
            client = authMSK.getAWSACMPCAClient(new AWSStaticCredentialsProvider(crossAccountCredentials));
        } else {
            logger.info("Setting up AWS ACM PCA client");
            client = authMSK.getAWSACMPCAClient(new AWSStaticCredentialsProvider(credentials));
        }

        if (!authMSK.getClientCertificate){

            if (authMSK.certificateArn != null){
                logger.info("Certificate Arn provided without the parameter --getClientCertificate(or -gcc). It will be ignored and a new certificate issued from ACM PCA.");
            }

            logger.info("Generating private key and certificate");
            CertAndKeyGen gen = authMSK.generateKeyPairAndCert();
            authMSK.createKeyStoreIfMissing(authMSK.keystoreType, authMSK.keystorePassword);
            if (authMSK.createPEMFiles){
                logger.info(String.format("Writing out private key to: %s\n", authMSK.privateKeyPEMFileLocation));
                authMSK.writePEMFile(authMSK.privateKeyPEMFileLocation, authMSK.getPrivateKeyinPEMFormat(gen));
            }

            X509Certificate [] privateKeyCertificateChain = authMSK.generateKeyCertificateChain(gen);
            logger.info(String.format("Storing key and certificate in keystore: %s with alias: %s\n", authMSK.keystoreLocation, authMSK.alias));
            authMSK.storeKeystoreKeyEntry(privateKeyCertificateChain, authMSK.alias, authMSK.keystorePassword, authMSK.keystoreType, gen.getPrivateKey());
            logger.info("Generating Certificate Signing Request");
            String csrReq = authMSK.generateCSR(gen);
            logger.info(String.format("CSR generated: \n%s\n", csrReq));
            logger.info("Getting certificate issued from ACM PCA");
            authMSK.certificateArn = authMSK.issueCertificate(authMSK.certificateAuthorityArn, csrReq, client);

        } else {
            if (authMSK.certificateArn == null){
                throw new ParameterException(
                        "Certificate Arn parameter (--certificateArn or -ca) needs to be specified.");
            }
        }

        logger.info(String.format("Getting Certificate with Arn: %s\n from Certificate Authority with Arn: %s\n", authMSK.certificateArn, authMSK.certificateAuthorityArn));
        String certChain = authMSK.getCertificate(authMSK.certificateArn, authMSK.certificateAuthorityArn, client);
        logger.info(String.format("Retrieved certificate chain: \n%s\n ", certChain));

        if (authMSK.createPEMFiles){
            logger.info(String.format("Writing out signed client certificate to: %s\n", authMSK.clientCertFileLocation));
            authMSK.writePEMFile(authMSK.clientCertFileLocation, authMSK.getClientCertificate(authMSK.certificateArn, authMSK.certificateAuthorityArn, client).getBytes());
        }

        logger.info("Converting into X509 certificate chain");
        X509Certificate [] certificateChain = authMSK.getCertChain(certChain);
        logger.info(String.format("Storing certificate in keystore: %s\n", authMSK.keystoreLocation));
        authMSK.storeKeystoreKeyEntry(certificateChain, authMSK.alias, authMSK.keystorePassword, authMSK.keystoreType, null);
    }
}
