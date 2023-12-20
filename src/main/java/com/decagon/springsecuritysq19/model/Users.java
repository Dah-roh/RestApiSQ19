package com.decagon.springsecuritysq19.model;

import com.decagon.springsecuritysq19.enums.Role;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Users implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name = "user-seq", initialValue = 2000)
    @JsonIgnore
    private Long id;
    @Column(unique = true)
    private String username;
    private String firstName;
    private String lastName;
    private String password;
    @Enumerated(value = EnumType.STRING)
    private Role userRole;


    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>(Collections.singleton(new SimpleGrantedAuthority(this.userRole.name())));
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
}
