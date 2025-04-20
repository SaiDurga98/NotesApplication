package com.techie.notes.service;

import com.techie.notes.models.User;
import com.techie.notes.dto.UserDTO;
import org.springframework.stereotype.Service;

import java.util.List;


public interface UserService {

    List<User> getAllUsers();

    void updateUserRole(Long userId, String roleName);

    UserDTO getUserById(Long userId);
}
