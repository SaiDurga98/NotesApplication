package com.techie.notes.service;

import com.techie.notes.models.Role;
import com.techie.notes.models.User;
import com.techie.notes.dto.UserDTO;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


public interface UserService {

    List<User> getAllUsers();

    void updateUserRole(Long userId, String roleName);

    UserDTO getUserById(Long userId);

    User findByUsername(String username);

    void updateAccountLockStatus(Long userId, boolean lock);

    List<Role> getAllRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String password);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String newPassword);

    Optional<User> findByEmail(String email);

    User registerUser(User newUser);

    GoogleAuthenticatorKey generate2FASecret(Long userId);

    boolean validate2FACode(Long userId, int code);

    void enable2FA(Long userId);

    void disable2FA(Long userId);
}
