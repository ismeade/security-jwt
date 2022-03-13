package com.exp.securityjwt.rest.vo;

import lombok.Data;

@Data
public class PasswordTokenRequest {

    private String username;
    private String password;

}
