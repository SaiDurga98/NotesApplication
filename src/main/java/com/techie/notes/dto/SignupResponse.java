package com.techie.notes.dto;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class SignupResponse {
    private String message;

    public SignupResponse(String message) {
        this.message = message;
    }

}
