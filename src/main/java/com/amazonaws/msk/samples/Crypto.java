package com.amazonaws.msk.samples;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import sun.security.pkcs10.PKCS10;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;
import java.io.*;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

class Crypto {

    private static final Logger logger = LogManager.getLogger(AuthMSK.class);


    void storeKeystoreKeyEntry(X509Certificate[] certificateChain, String alias, String password, String keystoreType, Key key, String keystoreLocation) throws Exception {
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

    CertAndKeyGen generateKeyPairAndCert() throws NoSuchAlgorithmException, InvalidKeyException {

        CertAndKeyGen gen = new CertAndKeyGen("RSA","SHA256WithRSA");
        gen.generate(2048);
        return gen;
    }

    void createKeyStoreIfMissing(String keystoreType, String password, String keystoreLocation) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {

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

    X509Certificate [] generateKeyCertificateChain(CertAndKeyGen gen, Long certificateValidity) throws IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {
        X509Certificate cert = gen.getSelfCertificate(new X500Name("CN=" + InetAddress.getLocalHost().getHostName()), certificateValidity *24*3600);

        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;
        return chain;
    }

    byte [] getPrivateKeyinPEMFormat(CertAndKeyGen gen){

        String keypem  = "-----BEGIN RSA PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(gen.getPrivateKey().getEncoded()) +
                "\n-----END RSA PRIVATE KEY-----\n";

        logger.info(keypem);
        return keypem.getBytes();
    }

    String generateCSR(CertAndKeyGen gen) throws IOException, InvalidKeyException, SignatureException {
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outStream);

        X500Name x500Name = new X500Name("CN=" + InetAddress.getLocalHost().getHostName());
        PKCS10 pkcs10CSR = gen.getCertRequest(x500Name);
        pkcs10CSR.print(printStream);
        return outStream.toString().replace("BEGIN NEW CERTIFICATE REQUEST", "BEGIN CERTIFICATE REQUEST").replace("END NEW CERTIFICATE REQUEST", "END CERTIFICATE REQUEST");
    }

    X509Certificate [] getCertChain(String certChain) throws CertificateException {
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
}
