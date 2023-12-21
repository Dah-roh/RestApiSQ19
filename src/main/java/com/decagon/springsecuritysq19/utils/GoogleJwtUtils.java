package com.decagon.springsecuritysq19.utils;
import com.decagon.springsecuritysq19.dto.UserDto;
import com.decagon.springsecuritysq19.enums.Role;
import com.decagon.springsecuritysq19.model.Users;
import com.decagon.springsecuritysq19.repositories.UserRepository;
import com.decagon.springsecuritysq19.serviceImpl.UserServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.function.Function;

@Component
public class GoogleJwtUtils {

    @Value("${CLIENT.ID}")
    private String CLIENT_ID;
    private UserRepository userRepository;
    private UserServiceImpl userService;
    private PasswordEncoder passwordEncoder;
    private JwtUtils utils;
    @Autowired
    public GoogleJwtUtils(UserRepository userRepository, @Lazy UserServiceImpl userService, PasswordEncoder passwordEncoder, JwtUtils utils) {
        this.userRepository = userRepository;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.utils = utils;
    }


    private final Function<String, UserDto> getUserFromIdToken = (token)-> {
        HttpTransport transport = new NetHttpTransport();
        JsonFactory jsonFactory = new GsonFactory();

        GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                .setAudience(Collections.singletonList(CLIENT_ID))
                .build();

        GoogleIdToken idToken = null;
        try {
            idToken = verifier.verify(token);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
        if (idToken != null) {
            Payload payload = idToken.getPayload();
            String userId = payload.getSubject();
            System.out.println("User ID: " + userId);

            String email = payload.getEmail();
//            boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
//            String name = (String) payload.get("name");
//            String pictureUrl = (String) payload.get("picture");
//            String locale = (String) payload.get("locale");
            String familyName = (String) payload.get("family_name");
            String givenName = (String) payload.get("given_name");
            return UserDto
                    .builder()
                    .username(email)
                    .firstName(givenName)
                    .lastName(familyName)
                    .password("GOOGLELOGIN")
                    .build();

        }
        return null;
    };

    public Function<UserDto, String> saveOauthUser = userDto -> {
        if (userRepository.existsByUsername(userDto.getUsername())){
            UserDetails userDetails = userService.loadUserByUsername(userDto.getUsername());
            return utils.createJwt.apply(userDetails);
        }
        else{
            Users user = new ObjectMapper().convertValue(userDto, Users.class);
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setUserRole(Role.ROLE_USER);
            user = userRepository.save(user);
            return utils.createJwt.apply(userService.loadUserByUsername(user.getUsername()));
        }
    };

    public String googleOauthUserJWT(String token){
        UserDto user =  getUserFromIdToken.apply(token);
        return saveOauthUser.apply(user);
    }
}
