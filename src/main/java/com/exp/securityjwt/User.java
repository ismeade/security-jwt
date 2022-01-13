package com.exp.securityjwt;

import lombok.Data;

import java.util.List;

@Data
public class User {

    private String name;
    private String password;
    private List<String> authorities;

}
