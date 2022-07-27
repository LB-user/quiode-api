package com.quiode.payload.request;

import javax.validation.constraints.NotBlank;
public class ResetPasswordRequest {
    @NotBlank
    private String resetToken;
    @NotBlank
    private String password;
    @NotBlank
    private String confirmPassword;

    public String getResetToken() {
        return resetToken;
    }

    public void setResetToken(String username) { this.resetToken = username; }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}