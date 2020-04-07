## Managing Client certificates for mutual authentication with Amazon MSK

It is a common security requirement to enable encryption-in-transit and authentication with Apache Kafka. Apache Kafka 
supports multiple authentication mechanisms including TLS mutual authentication using certificates, SASL 
(Simple Authorization Security Layer) PLAINTEXT, SASL SCRAM, SASL GSSAPI, SASL OAUTHBEARER. As or this writing, 
Amazon Managed Streaming for Apache Kafka (Amazon MSK) supports encryption in transit with TLS and TLS mutual authentication with 
certificates for client authentication. This code helps automate the process of creating and installing end-entity certificates 
and renewing them when they expire.

Amazon MSK utilizes Amazon Certificate Manager Private Certificate Authority (ACM PCA) for TLS mutual authentication. For information about 
Private Certificate Authoritys, see [Creating and Managing a Private CA](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaCreatingManagingCA.html)
and see [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) for information on Certificate Authorities.
The PCA can either be a [root Certificate Authority](https://en.wikipedia.org/wiki/Root_certificate) (CA) or a 
[subordinate Certificate Authority](https://www.ssl.com/article/subordinate-cas-and-why-you-might-need-one/). 
If it is a root CA, you need to install a self-signed certificate 
(the console provides an easy mechanism to do that). If it is a subordinate CA, you can either choose an ACM PCA root or
subordinate CA or an external CA (in this case, the external CA which can be your own CA will become the root of your 
certificate chain). In addition, for Amazon MSK to be able to use the ACM PCA, it needs to be in the same AWS account 
as the Amazon MSK cluster. However, the Apache Kafka clients, for ex. the producers and consumers, schema 
registries, Kafka Connect or other Apache Kafka tools that need the end-entity certificates can be in an AWS account 
different from the AWS account that the ACM PCA is in. In that scenario, in order to be able to access the ACM PCA, 
they need to assume a role in the account the ACM PCA is in and has the required permissions as the ACM PCA does not 
support resource-based policies, only identity-based policies.

If encryption in-transit is enabled for an Amazon MSK cluster, Public TLS certificates from ACM are installed in the
Amazon MSK Apache Kafka brokers in their keystores. If TLS mutual authentication is enabled for the Amazon MSK cluster, 
you need to provide the arn (Amazon resource number) of a Private CA in ACM that the Amazon MSK cluster can utilize. The 
CA certificate and the certificate chain of the specified PCA are retrieved and installed in the truststores of the 
Amazon MSK Apache Kafka brokers.

On the clients, you need to generate a Private Key and create a CSR (Certificate Signing Request) that are used to get 
end-entity certificates issued by the ACM PCA specified for an Amazon MSK cluster. These certificates and their 
certificate chains are installed in the keystores on the client and are trusted by the Amazon MSK Apache Kafka brokers. 
The steps are documented in [Client Authentication](https://docs.aws.amazon.com/msk/latest/developerguide/msk-authentication.html).


## Install

### Clone the repository and create the jar file.  

```
    git clone https://github.com/rcchakr/AuthMSK.git
    cd AuthMSK
    mvn clean package -f pom.xml
```  
    

The jar file accepts the following parameters:  

* **--help (or -h): help to get list of parameters**
* **-caa (or --certificateAuthorityArn) (mandatory)**: The Arn of the Private Certificate Authority in ACM to issue the end-client certificates.
* **-ksp (or --keystorePassword) (mandatory)**: The keystore password.
* **-reg (or --region)(Default us-east-1)**: AWS Region.
* **-ksl (or --keystoreLocation)(Default /tmp/kafka.client.keystore.jks)**: The location of the keystore file.
* **-ksa (or --alias)(Default msk)**: The alias of the key entry in the keystore.
* **-kst (or --keystoreType)(Default PKCS12)**: The keystore type.
* **-cfv (or --certificateValidity)(Default 300)**: The validity of the certificate to be issued in days.
* **-pem (or --createPEMFiles)**: Optional flag to create PEM files for the Private Key and the issued client certificate to be used by clients in python, node.js etc.
* **-pkf (or --privateKeyPEMFileLocation)(Default /tmp/private_key.pem)**: Specifies the Private Key PEM file location. Works in conjunction with **-pem** flag. Has no effect if the **-pem** flag is not specified.
* **-ccf (or --clientCertFileLocation)(Default /tmp/client_cert.pem)**: Specified the Client Certificate PEM file location. Works in conjunction with **-pem** flag. Has no effect if the **-pem** flag is not specified.
* **-cra (or --crossAccountRoleArn)**: Optional parameter that specifies an IAM Role in the ACM PCA account to assume when the client is in a different account from the ACM PCA.
* **-gcc (or --getClientCertificate)**: Optional flag denoting that the Private Key generation and certificate issuance can be skipped and 
      the certificate specified with the  **-cfa** parameter should be retrieved and installed in the keystore. 
      This can help with the renewal of certificates when ACM is authorized to auto-renew the PCA certificates.
* **-cfa (or --certificateArn)**: Specified the Arn of the ACM PCA certificate that needs to be retrieved and installed. 
      Needs to be specified if **-gcc** is specified. Works in conjunction with **-gcc** flag. Has no effect if the **-gcc** flag is not specified.
     
## Usage Examples

### To get the list of parameters

```
java -jar AuthMSK-1.0-SNAPSHOT.jar -h
```
### To generate the Private Key on the client, generate the csr, get a certificate issued by the ACM PCA and get and install the certificate in the keystore

```
java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias>
```

### To generate the Private Key on the client, generate the csr, get a certificate issued by the ACM PCA and get and install the certificate in the keystore with the ACM PCA in a region other than us-east-1

```
java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -reg <region> 
```

### To generate the Private Key on the client, generate the csr, get a certificate issued by the ACM PCA and get and install the certificate in the keystore of a type other than PKCS12 (eg. jks)

```
java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -kst <key store type>)
```

 ### To generate the Private Key on the client, generate the csr, get a certificate issued by the ACM PCA in a different account and get and install the certificate in the keystore
 ***To create a cross account role see [Tutorial](https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html).***
 
 With AWS CLI V2, you can use the following CLI commands to create a role in the remote account that can be used by clients in your current account:
 
```
aws iam create-role --role-name PCACrossAccountRole --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<current-account-id>:root"},"Action":"sts:AssumeRole"}]}'
aws iam create-policy --policy-name PCAPolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"PCA1","Effect":"Allow","Action":["acm-pca:IssueCertificate","acm-pca:GetCertificate","acm-pca:ListPermissions"],"Resource":"arn:aws:acm-pca:us-east-2:<remote-account-id>:certificate-authority/c135e36c-c457-4ba3-8fc7-cae6f52a7971"}]}'
aws iam attach-role-policy --role-name PCACrossAccountRole --policy-arn arn:aws:iam::<remote-account-id>:policy/PCAPolicy
```

Then in the current account, give a principal the ability to assume the role:

```
aws iam create-policy --policy-name PCACrossAccountAssumeRolePolicy --policy-document '{"Version":"2012-10-17","Statement":[{"Sid":"PCA2","Effect":"Allow","Action":"sts:assumeRole","Resource":"arn:aws:iam::<remote-account-id>:role/PCACrossAccountRole"}]}'
aws iam attach-role-policy --role-name <role-in-current-account> --policy-arn arn:aws:iam::<current-account-id>:policy/PCACrossAccountAssumeRolePolicy
```
 
 Then in the current account:
```
 java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -cra <cross account role arn>
```
 
### To just get and install a certificate using the certificate arn
***This can be useful for installing renewed certificates. When creating the ACM PCA or after creation, you can [authorize](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaPermissions.html) the ACM to be able to renew the PCA issued certificates.
Once renewed this can be used to get the renewed certificates and install in the keystore. The ACM PCA maintains the same arn for renewed certificates.***

```
 java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -gcc -cfa <certificate arn>
 ```

### To generate the Private Key on the client, generate the csr, get a certificate issued by the ACM PCA and get and install the certificate in the keystore and also generate PEM files for the Private Key and the issued certificate
***These PEM files can be used with Kafka clients in python, node.js and other languages for TLS encryption in-transit and mutual TLS authentication that cannot use the keystore and truststore.***

```
 java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -pem -pkf <Private Key PEM file location> -ccf <Client certificate PEM file location>
 ```

### To just get and install a certificate using the certificate arn and also generate the PEM file for the issued certificate
***These PEM files can be used with Kafka clients in python, node.js and other languages for TLS encryption in-transit and mutual TLS authentication that cannot use the keystore and truststore. In this case the assumption is
that the Private Key PEM file is already available.***

```
 java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl <full path of the keystore> -ksp <keystore password> -ksa <key entry alias> -pem -ccf <Client certificate PEM file location>
 ```

### Example of using kafka-python client with Amazon MSK with TLS mutual authentication

* On Linux:

    ```
    find /usr/lib/jvm/ -name "cacerts" -exec cp {} /tmp/kafka221/kafka.client.truststore.jks \;
    keytool --list -rfc -keystore /tmp/kafka.client.truststore.jks >/tmp/truststore.pem
    java -jar AuthMSK-1.0-SNAPSHOT.jar -caa <ACM PCA Arn> -ksl /tmp/kafka.client.keystore.jks -ksp password -ksa msk -pem -pkf /tmp/private_key.pem -ccf /tmp/certificate.pem
    ```
    Sample Python consumer code using kafka-python:
    
    ```
        from kafka import KafkaConsumer
        from kafka import TopicPartition
        TOPIC = "test"
        
        consumer = KafkaConsumer(bootstrap_servers='<msk bootstrap brokers for tls (port 9094)>',
                                # For encryption in transit
                                  security_protocol='SSL',
                                  ssl_cafile='/tmp/truststore.pem'
                                # For TLS mutual auth the above and:
                                  ssl_check_hostname=True,
                                  ssl_certfile='/tmp/client_cert.pem',
                                  ssl_keyfile='/tmp/private_key.pem')
                                # for the trustore copy the truststore from /etc/ssl/certs or the oracle jvm cacerts (find /usr/lib/jvm/ -name "cacerts" -exec cp {} /home/ec2-user/kafka/kafka.client.truststore.jks \;)
                                # to generate the the truststore.pem: keytool --list -rfc -keystore /home/ec2-user/kafka240/kafka.client.truststore.jks > truststore.pem 
        
        # Read and print all messages from test topic
        parts = consumer.partitions_for_topic(TOPIC)
        if parts is None:
           exit(1)
        partitions = [TopicPartition(TOPIC, p) for p in parts]
        consumer.assign(partitions)
        for  partition in partitions:
          consumer.seek_to_beginning(partition)
        for msg in consumer:
            print(msg)
    ```