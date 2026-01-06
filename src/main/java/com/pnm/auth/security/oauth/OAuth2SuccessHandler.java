package com.pnm.auth.security.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pnm.auth.dto.response.ApiResponse;

import com.pnm.auth.dto.result.AuthenticationResult;
import com.pnm.auth.web.context.RequestContext;
import com.pnm.auth.web.filter.RequestContextFilter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final OAuth2ServiceImpl oAuth2Service;

//    @Value("${app.oauth2.authorized-redirect-uris}")
//    private String frontendRedirectUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpRequest, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        log.info("OAuth2SuccessHandler: Authentication success event triggered");

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info("OAuth2SuccessHandler: Extracted OAuth2AuthenticationToken");

        OAuth2User oAuth2User = token.getPrincipal();
        log.info("OAuth2SuccessHandler: Extracted OAuth2User");

        String registrationId = token.getAuthorizedClientRegistrationId();
        log.info("OAuth2SuccessHandler: Provider={}", registrationId);

        RequestContext ctx = (RequestContext) httpRequest.getAttribute(RequestContextFilter.REQUEST_CONTEXT_ATTR);

        AuthenticationResult authResult =
                oAuth2Service.handleOAuth2LoginRequest(oAuth2User, registrationId, ctx);

        String path = ctx.path();

        ApiResponse<?> body;
        HttpStatus status;

        switch (authResult.getOutcome()) {

            case SUCCESS -> {
                body = ApiResponse.success(
                        "LOGIN_SUCCESS",
                        authResult.getMessage(),
                        authResult,
                        path
                );
                status = HttpStatus.OK;
            }

            case LINK_REQUIRED -> {
                body = ApiResponse.errorWithMeta(
                        "ACCOUNT_LINK_REQUIRED",
                        "This email is already registered. Do you want to link accounts?",
                        path,
                        Map.of(
                                "email", authResult.getEmail(),
                                "existingProvider", authResult.getExistingProvider().name(),
                                "attemptedProvider", authResult.getAttemptedProvider().name(),
                                "nextAction", authResult.getNextAction().name(),
                                "linkToken", authResult.getLinkToken()
                        )
                );
                status = HttpStatus.CONFLICT;
            }

            default -> {
                body = ApiResponse.error(
                        "LOGIN_FAILED",
                        authResult.getMessage(),
                        path
                );
                status = HttpStatus.UNAUTHORIZED;
            }
        }


        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(body));

        log.info("OAuth2SuccessHandler: Response sent for OAuth provider={}", registrationId);

//        AuthenticationResult authResult = oAuth2Service.handleOAuth2LoginRequest(oAuth2User, registrationId, request);
//
//        // 🚨 FIX: Redirect to Frontend with Token in URL Query Param
//        String targetUrl = UriComponentsBuilder.fromUriString(frontendRedirectUrl)
//                .queryParam("token", authResult.getToken()) // Or refreshToken
//                .queryParam("error", authResult.getOutcome() == AuthOutcome.SUCCESS ? "" : "link_required")
//                .build().toUriString();
//
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
