package com.pnm.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UpdateProfileRequest {

    @NotBlank
    private String fullName;

//     In future
//     private String phone;
//     private String profilePictureUrl;
//     private String address;
}
