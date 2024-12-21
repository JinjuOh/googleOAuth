package com.jinjuoh.googleoauth.config;

import com.jinjuoh.googleoauth.TokenFilter;
import com.jinjuoh.googleoauth.service.TokenService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final TokenFilter tokenFilter;
    private final TokenService tokenService;

    public SecurityConfig(TokenFilter tokenFilter, TokenService tokenService) {
        this.tokenFilter = tokenFilter;
        this.tokenService = tokenService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/","/login", "/oauth2/**", "/logout").permitAll() // 인증 없이 허용
                        .anyRequest().authenticated() // 그 외 요청은 인증 필요
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(new OAuth2LoginSuccessHandler(tokenService))
                )
                .addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler((request, response, authentication) -> {
                            if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
                                String userId = ((OidcUser) authentication.getPrincipal()).getSubject();
                                tokenService.deleteTokens(userId);
                            }
                        })
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                        })
                )
                .requestCache(
                        requestCache -> requestCache.requestCache(new HttpSessionRequestCache())
                )
        ;

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManager.class);
    }
}
