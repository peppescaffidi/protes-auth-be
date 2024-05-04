package com.protes.protesauthbe.model;

import lombok.Data;

@Data
public class AuthRequestDTO {
    private String email;
    private String username;
    private String password;
}
