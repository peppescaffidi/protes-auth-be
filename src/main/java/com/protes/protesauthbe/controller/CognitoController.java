package com.protes.protesauthbe.controller;

import com.protes.protesauthbe.model.AuthRequestDTO;
import com.protes.protesauthbe.model.AuthResponseDTO;
import com.protes.protesauthbe.service.CognitoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InitiateAuthResponse;

@CrossOrigin(maxAge = 3600)
@RestController
@RequestMapping("/auth")
public class CognitoController {
    @Autowired
    CognitoService cognitoService;

    @PostMapping("/sign-in")
    public AuthResponseDTO initiateAuth(@RequestBody AuthRequestDTO authRequestDTO) {
        AuthResponseDTO authResponseDTO = new AuthResponseDTO();
        try {
            InitiateAuthResponse initiateAuthResponse = cognitoService.initiateAuth(authRequestDTO);

            authResponseDTO.setUsername(authRequestDTO.getUsername());
            authResponseDTO.setToken(initiateAuthResponse.authenticationResult().idToken());

        } catch (Exception e) {
            System.err.println("Exception: " + e);
        }
        return authResponseDTO;
    }
}
