package com.techie.notes.config;


import com.techie.notes.dto.LoginRequest;
import com.techie.notes.dto.LoginResponse;
import com.techie.notes.security.services.UserDetailsImpl;
import com.techie.notes.security.services.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/public/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try{
            // Initializing the authentication object
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (Exception e) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }
        // Setting the security context holder to new authentication object
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // Getting the UserDetails from authentication object
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        // Generated the jwt token from userDetails
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
        // Fetching the roles
        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority()).collect(Collectors.toList());
        // Creating the response object with username, roles and jwt token
        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);

        return new ResponseEntity<>(response, HttpStatus.OK);


    }

}
