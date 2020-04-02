package com.amazonaws.msk.samples;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import com.amazonaws.services.securitytoken.model.AssumeRoleRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleResult;

class Credentials {

     AWSCredentials getAWSCredentials(){
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

    BasicSessionCredentials crossAccountAssumeRole(AWSCredentialsProvider credentials, String region, String crossAccountRoleArn){

        AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                .withRegion(region)
                .withCredentials(credentials)
                .build();

        AssumeRoleRequest assumeRoleRequest = new AssumeRoleRequest();
        assumeRoleRequest.withDurationSeconds(3600)
                .withRoleArn(crossAccountRoleArn)
                .withRoleSessionName("AssumeRolePCA");

        AssumeRoleResult assumeRoleResult = stsClient.assumeRole(assumeRoleRequest);
        com.amazonaws.services.securitytoken.model.Credentials assumeRoleCredentials = assumeRoleResult.getCredentials();
        return new BasicSessionCredentials(assumeRoleCredentials.getAccessKeyId(), assumeRoleCredentials.getSecretAccessKey(), assumeRoleCredentials.getSessionToken());
    }
}
