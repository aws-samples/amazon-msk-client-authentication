package com.amazonaws.msk.samples;

import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.client.builder.AwsClientBuilder.EndpointConfiguration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;


import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder;

import com.amazonaws.services.acmpca.model.*;

import java.io.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.amazonaws.AmazonClientException;
import com.amazonaws.waiters.Waiter;
import com.amazonaws.waiters.WaiterParameters;
import com.amazonaws.waiters.WaiterTimedOutException;
import com.amazonaws.waiters.WaiterUnrecoverableException;
import sun.security.pkcs10.PKCS10;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;




public class AuthMSK {

    final String endpointProtocol = "acm-pca.us-east-1.amazonaws.com";
    final String endpointRegion = "us-east-1";
    final String keystoreLocation = "/home/ec2-user/kafka240/kafka.client.keystore.jks";
    //final String keystoreLocation = "/Users/rcchakr/kafka.client.keystore.jks";

    private AWSCredentials getAWSCredentials(){
        AWSCredentials credentials = null;
        try {
            credentials = new ProfileCredentialsProvider("default").getCredentials();
        } catch (Exception e) {
            throw new AmazonClientException(
                    "Cannot load the credentials from the credential profiles file. " +
                            "Please make sure that your credentials file is at the correct " +
                            "location (~/.aws/credentials), and is in valid format.",
                    e);
        }
        return credentials;
    }

    private void deleteCertificateAuthority(String certificateAuthorityArn, Integer permanentDeletionTimeInDays, AWSACMPCA client){

        DeleteCertificateAuthorityRequest deleteCertificateAuthorityRequest = new DeleteCertificateAuthorityRequest();
        deleteCertificateAuthorityRequest
                .withCertificateAuthorityArn(certificateAuthorityArn)
                .withPermanentDeletionTimeInDays(permanentDeletionTimeInDays);

        DeleteCertificateAuthorityResult result;
        try {
            result = client.deleteCertificateAuthority(deleteCertificateAuthorityRequest);
        }
        catch (InvalidArgsException ex)
        {
            throw ex;
        }
        catch (InvalidPolicyException ex)
        {
            throw ex;
        }
        catch (LimitExceededException ex)
        {
            throw ex;
        }
        System.out.println(result);

    }

    private AWSACMPCA getAWSACMPCAClient(){
        // Define the endpoint for your sample.
        EndpointConfiguration endpoint =
                new AwsClientBuilder.EndpointConfiguration(endpointProtocol, endpointRegion);

        // Create a client that you can use to make requests.
        AWSACMPCA client = AWSACMPCAClientBuilder.standard()
                .withEndpointConfiguration(endpoint)
                .withCredentials(new AWSStaticCredentialsProvider(getAWSCredentials()))
                .build();
        return client;

    }

    private String createCertificateAuthority(AWSACMPCA client){


        // Define a CA subject.
        ASN1Subject subject = new ASN1Subject();
        subject.setOrganization("Amazon");
        subject.setOrganizationalUnit("AWS");
        subject.setCountry("US");
        subject.setState("New York");
        subject.setLocality("New York City");
        subject.setCommonName("MyPCA1");

        // Define the CA configuration.
        CertificateAuthorityConfiguration configCA = new CertificateAuthorityConfiguration();
        configCA.withKeyAlgorithm(KeyAlgorithm.RSA_2048);
        configCA.withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA);
        configCA.withSubject(subject);

        // Define a certificate revocation list configuration.
//        CrlConfiguration crlConfigure = new CrlConfiguration();
//        crlConfigure.withEnabled(true);
//        crlConfigure.withExpirationInDays(365);
//        crlConfigure.withCustomCname(null);
//        crlConfigure.withS3BucketName("your-bucket-name");

        //RevocationConfiguration revokeConfig = new RevocationConfiguration();
        //revokeConfig.setCrlConfiguration(crlConfigure);

        // Define a certificate authority type
        CertificateAuthorityType CAtype = CertificateAuthorityType.ROOT;

        // Create a tag - method 1
        Tag tag1 = new Tag();
        tag1.withKey("PrivateCA");
        tag1.withValue("Sample");

        // Create a tag - method 2
        Tag tag2 = new Tag()
                .withKey("Purpose")
                .withValue("MSK");

        // Add the tags to a collection.
        ArrayList<Tag> tags = new ArrayList<Tag>();
        tags.add(tag1);
        tags.add(tag2);

        // Create the request object.
        CreateCertificateAuthorityRequest req = new CreateCertificateAuthorityRequest();
        req.withCertificateAuthorityConfiguration(configCA);
        //req.withRevocationConfiguration(revokeConfig);
        req.withIdempotencyToken("123987");
        req.withCertificateAuthorityType(CAtype);
        req.withTags(tags);


        // Create the private CA.
        CreateCertificateAuthorityResult result = null;
        try {
            result = client.createCertificateAuthority(req);
        }
        catch (InvalidArgsException ex)
        {
            throw ex;
        }
        catch (InvalidPolicyException ex)
        {
            throw ex;
        }
        catch (LimitExceededException ex)
        {
            throw ex;
        }

        // Retrieve the ARN of the private CA.
        String arn = result.getCertificateAuthorityArn();
        System.out.println(arn);

        return arn;
    }

    private KeyPair generateKeyPair(String algorithm, int keySize){

        try {
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(keySize);
            return keyPairGenerator.generateKeyPair();

        } catch (Exception exception){
            exception.printStackTrace();
        }
        return null;
    }

    private void storeKeystoreClientCertificate(X509Certificate [] certificateChain) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {

        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream(keystoreLocation), "password".toCharArray());
            //System.out.println(cert.toString());

            keystore.setKeyEntry("msk", keystore.getKey("msk", "password".toCharArray()), "password".toCharArray(), certificateChain);
            keystore.store(new FileOutputStream(keystoreLocation), "password".toCharArray());
        } catch (KeyStoreException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (CertificateException e) {
            throw e;
        } catch (UnrecoverableKeyException e) {
            throw e;
        }
    }

    private CertAndKeyGen generateKeyPairAndCert(){
        try {
            CertAndKeyGen gen = new CertAndKeyGen("RSA","SHA1WithRSA");
            gen.generate(2048);
            return gen;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    private CertAndKeyGen createKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException, NoSuchProviderException {


        try {
            //KeyPair keyPair = generateKeyPair("RSA", 2048);
            CertAndKeyGen gen = generateKeyPairAndCert();
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            //KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(null, null);
            InetAddress.getLocalHost().getHostName();

            X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=" + InetAddress.getLocalHost().getHostName()), (long)365*24*3600);

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;
            keystore.setKeyEntry("msk", gen.getPrivateKey(), "password".toCharArray(), chain);
            keystore.store(new FileOutputStream(keystoreLocation), "password".toCharArray());
            return gen;
        } catch (KeyStoreException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        } catch (NoSuchAlgorithmException e) {
            throw e;
        } catch (CertificateException e) {
            throw e;
        } catch (InvalidKeyException e) {
            throw e;
        } catch (SignatureException e) {
            throw e;
        } catch (NoSuchProviderException e) {
            throw e;
        }

    }

    private String generateCSR() throws KeyStoreException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);
        try {
            CertAndKeyGen gen = createKeyStore();
            X500Name x500Name = new X500Name("CN=" + InetAddress.getLocalHost().getHostName());
            PKCS10 pkcs10CSR = gen.getCertRequest(x500Name);
            pkcs10CSR.print(printStream);
            String csrReq = outStream.toString().replace("BEGIN NEW CERTIFICATE REQUEST", "BEGIN CERTIFICATE REQUEST").replace("END NEW CERTIFICATE REQUEST", "END CERTIFICATE REQUEST");
            return csrReq;
        } catch (KeyStoreException e) {
            throw e;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static ByteBuffer stringToByteBuffer(final String string) {
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
                                            .withValue(300L))
                .withIdempotencyToken("1234");

        IssueCertificateResult issueCertificateResult = null;
        try {
            issueCertificateResult = client.issueCertificate(issueCertificateRequest);
            System.out.println(issueCertificateResult.getCertificateArn());
            return issueCertificateResult.getCertificateArn();
        } catch(LimitExceededException ex)
        {
            ex.printStackTrace();
        }
        catch(ResourceNotFoundException ex)
        {
            ex.printStackTrace();
        }
        catch(InvalidStateException ex)
        {
            ex.printStackTrace();
        }
        catch (InvalidArnException ex)
        {
            ex.printStackTrace();
        }
        catch (InvalidArgsException ex)
        {
            ex.printStackTrace();
        }
        catch (MalformedCSRException ex)
        {
            ex.printStackTrace();
        }
        return null;
    }

    private String getCertificate(String certificateArn, String certificateAuthorityArn, AWSACMPCA client) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        getCertificateRequest.withCertificateArn(certificateArn)
                .withCertificateAuthorityArn(certificateAuthorityArn);

        // Create waiter to wait on successful creation of the certificate file.
        Waiter<GetCertificateRequest> waiter = client.waiters().certificateIssued();
        try {
            waiter.run(new WaiterParameters<>(getCertificateRequest));
        } catch(WaiterUnrecoverableException e) {
            //Explicit short circuit when the recourse transitions into
            //an undesired state.
            throw e;
        } catch(WaiterTimedOutException e) {
            //Failed to transition into desired state even after polling.
            throw e;
        } catch(AWSACMPCAException e) {
            //Unexpected service exception.
            throw e;
        }

        GetCertificateResult getCertificateResult = null;

        try {
            getCertificateResult = client.getCertificate(getCertificateRequest);
            //System.out.println("Certificate: " + getCertificateResult.getCertificate());
            //System.out.println("Certificate chain: " + getCertificateResult.getCertificateChain());

            //System.out.println(getCertificateResult.getCertificateChain());
            return (getCertificateResult.getCertificate() + "\n" + getCertificateResult.getCertificateChain());
        } catch (RequestInProgressException ex) {
            throw ex;
        } catch (RequestFailedException ex) {
            throw ex;
        } catch (ResourceNotFoundException ex) {
            throw ex;
        } catch (InvalidArnException ex) {
            throw ex;
        } catch (InvalidStateException ex) {
            throw ex;
        }

    }
    private X509Certificate [] getCertChain(String certChain) throws CertificateException {
        Integer fromIndex = 0;
        List<String> certs = new ArrayList<String>();
        Integer addVal = 0;

        while (certChain.indexOf("-----BEGIN CERTIFICATE-----\n", fromIndex) != -1) {
            Integer beginIndex = certChain.indexOf("-----BEGIN CERTIFICATE-----\n", fromIndex);
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
        Integer i = 0;

        for (String cert: certs) {
            X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certs.get(i).getBytes()));
            x509Certificate.checkValidity();
            chain[i] = x509Certificate;
            i++;
        }

        return chain;
    }

    public static void main(String[] args) throws Exception{

        //String certificateAuthorityArn = "arn:aws:acm-pca:us-east-1:862656071619:certificate-authority/63d9d5b5-e39e-4135-a2d4-6d1ad9940240";
        String certificateAuthorityArn = "arn:aws:acm-pca:us-east-1:862656071619:certificate-authority/1084d669-c85d-49f5-8be8-a5a34d7f92bf";
        //String certificateArn = "arn:aws:acm-pca:us-east-1:862656071619:certificate-authority/63d9d5b5-e39e-4135-a2d4-6d1ad9940240/certificate/1f77f6345879ad591638161ea11a1779";
        //arn:aws:acm-pca:us-east-1:862656071619:certificate-authority/63d9d5b5-e39e-4135-a2d4-6d1ad9940240/certificate/1887e9a4fb40f1269b68b37f089001b9 - use next

        AuthMSK authMSK = new AuthMSK();
        AWSACMPCA client = authMSK.getAWSACMPCAClient();
        //authMSK.createCertificateAuthority(client);
        String csrReq = authMSK.generateCSR();
        //System.out.println(csrReq);
        String certificateArn = authMSK.issueCertificate(certificateAuthorityArn, csrReq, client);
        System.out.println(certificateArn);
        String certChain = authMSK.getCertificate(certificateArn, certificateAuthorityArn, client);
        //System.out.println(certificate);
        X509Certificate [] certificateChain = authMSK.getCertChain(certChain);
        authMSK.storeKeystoreClientCertificate(certificateChain);
        //byte[] csr = authMSK.generateCSR("SHA256WithRSA", authMSK.createKeyStore());
    }
}
