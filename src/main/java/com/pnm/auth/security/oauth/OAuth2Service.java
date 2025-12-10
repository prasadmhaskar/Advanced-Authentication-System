package com.pnm.auth.security.oauth;

import com.pnm.auth.dto.response.AuthResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuth2Service {
     AuthResponse handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId, HttpServletRequest request);
}
