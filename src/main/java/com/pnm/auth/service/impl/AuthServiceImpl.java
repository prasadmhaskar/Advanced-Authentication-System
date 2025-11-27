package com.pnm.auth.service.impl;

import com.pnm.auth.dto.request.LoginRequest;
import com.pnm.auth.dto.request.RefreshTokenRequest;
import com.pnm.auth.dto.request.RegisterRequest;
import com.pnm.auth.dto.request.ResetPasswordRequest;
import com.pnm.auth.dto.response.AuthResponse;
import com.pnm.auth.entity.User;
import com.pnm.auth.entity.VerificationToken;
import com.pnm.auth.enums.AuthProviderType;
import com.pnm.auth.exception.InvalidCredentialsException;
import com.pnm.auth.exception.InvalidTokenException;
import com.pnm.auth.exception.UserAlreadyExistsException;
import com.pnm.auth.exception.UserNotFoundException;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.repository.VerificationTokenRepository;
import com.pnm.auth.service.AuthService;
import com.pnm.auth.service.EmailService;
import com.pnm.auth.service.VerificationService;
import com.pnm.auth.util.JwtUtil;
import com.pnm.auth.util.OAuth2Util;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final VerificationService verificationService;
    private final EmailService emailService;
    private final JwtUtil jwtUtil;
    private final VerificationTokenRepository verificationTokenRepository;
    private final OAuth2Util oAuth2Util;
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
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        return new AuthResponse("Login successful", newAccessToken, newRefreshToken);

    }

    @Override
    public AuthResponse refreshToken(RefreshTokenRequest refreshToken) {

        String token = refreshToken.getRefreshToken();

        // Check expiration
        if(jwtUtil.isTokenExpired(token)){
        throw new InvalidTokenException("Token is expired");
        }

        // Extract email from refresh token
        String email = jwtUtil.extractUsername(token);

        // Load user from DB
        User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));

        // Generate new tokens
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        return new AuthResponse("Token refreshed successfully", newAccessToken, newRefreshToken);

    }

    @Override
    public void forgotPassword(String email) {

        User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));
        String token = verificationService.createVerificationToken(user, "PASSWORD_RESET");
        emailService.sendPasswordResetEmail(user.getEmail(), token);
    }

    @Override
    public void resetPassword(ResetPasswordRequest request) {
        String token = request.getToken();

        // 1. Validate token
        VerificationToken verificationToken = verificationTokenRepository.findByToken(token).orElseThrow(() -> new InvalidTokenException("Invalid token"));

        // 2. Check type
        if (!verificationToken.getType().equals("PASSWORD_RESET")){
            throw new InvalidTokenException("Token type mismatch");
        }

        // 3. Check expiration
        if (verificationToken.getExpiresAt().isBefore(LocalDateTime.now())){
            throw new InvalidTokenException("Token expired");
        }

        // 4. Load user from DB
        User user = verificationToken.getUser();

        // 5. Encode new password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // 6. Save user
        userRepository.save(user);

        // 7. Delete token after use (important)
        verificationTokenRepository.delete(verificationToken);

    }

    public AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {
        AuthProviderType providerType = oAuth2Util.getProviderTypeFromRegistrationId(registrationId);
        String providerId = oAuth2Util.determineProviderIdFromOAuth2User(oAuth2User, registrationId);

        User user = userRepository.findByProviderIdAndAuthProviderType(providerId, providerType).orElse(null);
        String email = oAuth2User.getAttribute("email");
        User emailUser = (email != null) ? userRepository.findByEmail(email).orElse(null) : null;

        if (user == null && emailUser == null) {
            // Create new user
            String username = oAuth2Util.determineUsernameFromOAuth2User(oAuth2User, registrationId);
            user = new User();
            user.setFullName(username);
            user.setPassword(username);
            user.setEmail(email);
            user.setProviderId(providerId);
            user.setAuthProviderType(providerType);
            user.setRoles(List.of("USER"));
            userRepository.save(user);
        } else if (user == null && emailUser != null) {
            // Email exists
            throw new UserAlreadyExistsException("The email: "+email+" is already registered. Do you want to merge both accounts?");
        }
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = jwtUtil.generateRefreshToken(user);
        return new AuthResponse("Login successful using OAuth2", newAccessToken, newRefreshToken);
    }
}
