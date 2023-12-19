package com.decagon.springsecuritysq19.dto;

import com.decagon.springsecuritysq19.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder@AllArgsConstructor
@NoArgsConstructor
public class UserDto {
    private String username;
    private String password;
    private String firstName;
    private String lastName;
    private Role userRole;

}
