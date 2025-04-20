package com.techie.notes.security.services;


import com.techie.notes.models.User;
import com.techie.notes.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;
    // Here we have to give our get the user related info through our
    // persistent storage and then convert into UserDetails which can be
    // understood by spring security. So we create UserDetailsServiceImpl
    // and UserDetailsImpl which implements spring Security core modules
    // responsible for authenticating users

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
     User user = userRepository.findByUserName(username)
             .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

     return UserDetailsImpl.build(user);
    }
}
