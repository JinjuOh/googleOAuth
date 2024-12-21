package com.jinjuoh.googleoauth.config;

import com.jinjuoh.googleoauth.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final TokenService tokenService;

    public OAuth2LoginSuccessHandler(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException {
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

        // 성공 후 리다이렉트 처리
        response.sendRedirect("/"); // 원하는 경로로 리다이렉트
    }
}
