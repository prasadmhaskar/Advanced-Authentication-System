package com.pnm.auth.security.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;
import com.pnm.auth.dto.response.AuthResponse;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final OAuth2ServiceImpl oAuth2ServiceImpl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        log.info("OAuth2SuccessHandler: Authentication success event triggered");

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info("OAuth2SuccessHandler: Extracted OAuth2AuthenticationToken");

        OAuth2User oAuth2User = token.getPrincipal();
        log.info("OAuth2SuccessHandler: Extracted OAuth2User");

        String registrationId = token.getAuthorizedClientRegistrationId();
        log.info("OAuth2SuccessHandler: Provider={}", registrationId);

        AuthResponse authResponse = oAuth2ServiceImpl.handleOAuth2LoginRequest(oAuth2User, registrationId, request);
//        log.info("OAuth2SuccessHandler: OAuth2Service returned AuthResponse");
//
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
//
//        log.info("OAuth2SuccessHandler: AuthResponse written to client");

        ApiResponse<AuthResponse> apiResponse = ApiResponse.success(
                "OAUTH2_LOGIN_SUCCESSFUL",
                authResponse.getMessage(),
                authResponse,
                request.getRequestURI()
        );

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));

        log.info("OAuth2SuccessHandler: Response sent for OAuth provider={}", registrationId);
    }
}
