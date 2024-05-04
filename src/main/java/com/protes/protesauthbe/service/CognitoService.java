package com.protes.protesauthbe.service;

import com.protes.protesauthbe.model.AuthRequestDTO;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;

public interface CognitoService {
    InitiateAuthResponse initiateAuth(AuthRequestDTO authRequestDTO);
}
