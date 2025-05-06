package com.techie.notes.util;


import com.techie.notes.models.User;
import com.techie.notes.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthUtil {

    @Autowired
    UserRepository userRepository;

    public Long loggedInUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User user = userRepository.findByUserName(auth.getName())
                .orElseThrow(() -> new RuntimeException("User Not Found"));
        return user.getUserId();
    }


    public User loggedInUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return userRepository.findByUserName(auth.getName())
                .orElseThrow(() -> new RuntimeException("User Not Found"));

    }




}
