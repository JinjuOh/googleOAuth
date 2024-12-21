package com.jinjuoh.googleoauth.config;

import com.jinjuoh.googleoauth.service.TokenService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.Principal;

@Component
public class OAuth2LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    private final TokenService tokenService;

    public OAuth2LoginSuccessHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (authentication.getPrincipal() instanceof OidcUser) {
            OidcUser oidcUser = (OidcUser) authentication.getPrincipal();

            String userId = oidcUser.getSubject(); // 사용자 고유 ID
            String accessToken = oidcUser.getIdToken().getTokenValue(); // Access Token
            String refreshToken = oidcUser.getAttribute("refresh_token"); // Refresh Token (필요 시 커스터마이즈)

            // Redis에 토큰 저장
            tokenService.saveAccessToken(userId, accessToken);
            if (refreshToken != null) {
                tokenService.saveRefreshToken(userId, refreshToken);
            }
        }

        SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
        if (savedRequest != null) {
            System.out.println("SavedRequest URL: " + savedRequest.getRedirectUrl());
        }
        System.out.println("Authentication after success: " + SecurityContextHolder.getContext().getAuthentication());

        // SavedRequestAwareAuthenticationSuccessHandler로 리디렉트 처리
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/"); // 기본 리디렉트 경로
        successHandler.onAuthenticationSuccess(request, response, authentication);
    }
}
