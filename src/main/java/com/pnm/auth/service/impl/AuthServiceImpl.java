package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.entity.User;
import com.pnm.auth.exception.InvalidCredentialsException;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.exception.UserAlreadyExistsException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.AuthService;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.VerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public AuthResponse register(RegisterRequest request) {

        String email = request.getEmail().trim().toLowerCase();

        if (userRepository.findByEmail(email).isPresent()) {
            throw new UserAlreadyExistsException("The email: " + email + " is already registered. Login using your email");
        }
        else {
            User user = new User();

            user.setFullName(request.getFullName());
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setRoles(List.of("USER"));
            userRepository.save(user);
            //Creating verification token
            String token = verificationService.createVerificationToken(user, "EMAIL_VERIFICATION");
            //Sending email to user with verification link
            emailService.sendVerificationEmail(user.getEmail(), token);
            return new AuthResponse("Registration successful. Please verify email.", null, null);

        }
    }
    @Override
    public AuthResponse login(LoginRequest request) {
        String email = request.getEmail().trim().toLowerCase();
        //Check user in db
        User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

        //Check password matches or not
        if(!passwordEncoder.matches(request.getPassword(), user.getPassword())){
            throw new InvalidCredentialsException("Wrong password. Please enter correct password");
        }

        //Check email is verified or not
        if(!user.getEmailVerified()){
            throw new InvalidTokenException("Verify email first");
        }

        return new AuthResponse("Login successful", "dummy-token", null);



    }

    @Override
    public AuthResponse refreshToken(String refreshToken) {
        return null;
    }
}
