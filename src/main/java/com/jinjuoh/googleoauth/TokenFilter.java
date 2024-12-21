package com.jinjuoh.googleoauth;

import com.jinjuoh.googleoauth.service.TokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class TokenFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    public TokenFilter(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 현재 인증 상태 확인 및 처리
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser)) {
            // Google OAuth2 사용자 정보 가져오기
            OidcUser oidcUser = (authentication != null && authentication.getPrincipal() instanceof OidcUser)
                    ? (OidcUser) authentication.getPrincipal()
                    : null;

            if (oidcUser != null) {
                String userId = oidcUser.getSubject(); // Google 사용자 ID

                // Access Token 검증
                String token = tokenService.getAccessToken(userId);
                if (token != null) {
                    // 권한 정보 설정
                    List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userId, null, authorities);

                    // SecurityContextHolder에 인증 객체 설정
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        }

        filterChain.doFilter(request, response);
    }

}
