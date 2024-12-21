package com.jinjuoh.googleoauth.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenService {

    private final StringRedisTemplate redisTemplate;

    // Access Token 만료 시간 (초)
    private static final long ACCESS_TOKEN_EXPIRY_SECONDS = 60 * 60; // 1시간 // 1시간

    // Refresh Token 만료 시간 (초)
    private static final long REFRESH_TOKEN_EXPIRY_SECONDS = 60 * 60 * 24 * 30; // 30일 // 30일

    public TokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Access Token 저장
     */
    public void saveAccessToken(String userId, String accessToken) {
        redisTemplate.opsForValue().set(
                "accessToken:" + userId,
                accessToken,
                ACCESS_TOKEN_EXPIRY_SECONDS,
                TimeUnit.SECONDS
        );
    }

    /**
     * Refresh Token 저장
     */
    public void saveRefreshToken(String userId, String refreshToken) {
        redisTemplate.opsForValue().set(
                "refreshToken:" + userId,
                refreshToken,
                REFRESH_TOKEN_EXPIRY_SECONDS,
                TimeUnit.SECONDS
        );
    }

    /**
     * Access Token 가져오기
     */
    public String getAccessToken(String userId) {
        return redisTemplate.opsForValue().get("accessToken:" + userId);
    }

    /**
     * Refresh Token 가져오기
     */
    public String getRefreshToken(String userId) {
        return redisTemplate.opsForValue().get("refreshToken:" + userId);
    }

    /**
     * 사용자 토큰 삭제
     */
    public void deleteTokens(String userId) {
        redisTemplate.delete("accessToken:" + userId);
        redisTemplate.delete("refreshToken:" + userId);
    }
}
