package com.protes.protesauthbe.service.impl;

import com.protes.protesauthbe.model.AuthRequestDTO;
import com.protes.protesauthbe.service.CognitoService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class CognitoServiceImpl implements CognitoService {
    @Value("${aws.cognito.userpoolclientid}")
    String userPoolClientId;
    @Value("${aws.cognito.userpoolsecretclientid}")
    String userPoolClientSecret;

    @Override
    public InitiateAuthResponse initiateAuth(AuthRequestDTO authRequestDTO) {
        try {
            CognitoIdentityProviderClient identityProviderClient = CognitoIdentityProviderClient.builder()
                    .region(Region.EU_NORTH_1)
                    .build();

            Map<String, String> authParameters = new HashMap<>();
            authParameters.put("USERNAME", authRequestDTO.getUsername());
            authParameters.put("PASSWORD", authRequestDTO.getPassword());

            String secretHash = calculateSecretHash(userPoolClientId, userPoolClientSecret, authRequestDTO.getUsername());
            authParameters.put("SECRET_HASH", secretHash);

            InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(authParameters)
                    .clientId(userPoolClientId)
                    .build();

            InitiateAuthResponse response = identityProviderClient.initiateAuth(initiateAuthRequest);

            System.out.println("Result Challenge is : " + response.challengeName());

            if (response.challengeName() != null) {
                if (response.challengeName().name().equals(ChallengeNameType.NEW_PASSWORD_REQUIRED.toString())) {
                    String name = authRequestDTO.getUsername();
                    String password = authRequestDTO.getPassword();
                    String email = authRequestDTO.getEmail();

                    RespondToAuthChallengeRequest respondToAuthChallengeRequest = RespondToAuthChallengeRequest.builder()
                            .clientId(userPoolClientId)
                            .challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                            .session(response.session())
                            .challengeResponses(
                                    Map.of(
                                            "USERNAME", name,
                                            "NEW_PASSWORD", password,
                                            "SECRET_HASH", secretHash,
                                            "userAttributes.name", name,
                                            "userAttributes.email", email
                                    )
                            )
                            .build();

                    identityProviderClient.respondToAuthChallenge(respondToAuthChallengeRequest);
                }
            }

            identityProviderClient.close();

            return response;

        } catch (CognitoIdentityProviderException e) {
            System.err.println(e.awsErrorDetails().errorMessage());
        }

        return null;
    }

    public static String calculateSecretHash(String userPoolClientId, String userPoolClientSecret, String username) {
        final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

        SecretKeySpec signingKey = new SecretKeySpec(
                userPoolClientSecret.getBytes(StandardCharsets.UTF_8),
                HMAC_SHA256_ALGORITHM);
        try {
            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);
            mac.update(username.getBytes(StandardCharsets.UTF_8));
            byte[] rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(rawHmac);
        } catch (Exception e) {
            throw new RuntimeException("Error while calculating ");
        }
    }
}
