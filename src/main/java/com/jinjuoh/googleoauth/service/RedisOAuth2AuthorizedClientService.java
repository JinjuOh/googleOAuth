package com.jinjuoh.googleoauth.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class RedisOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private final RedisTemplate<String, OAuth2AuthorizedClient> redisTemplate;

    public RedisOAuth2AuthorizedClientService(RedisTemplate<String, OAuth2AuthorizedClient> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        // Save the authorized client
        long refreshTokenExpiresAt = 7 * 24 * 60 * 60; // 7 days
        String key = generateKey(authorizedClient.getClientRegistration().getRegistrationId(), principal.getName());
        redisTemplate.opsForValue().set(key, authorizedClient, refreshTokenExpiresAt, TimeUnit.SECONDS);
    }

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        // Load the authorized client
        String key = generateKey(clientRegistrationId, principalName);
        return (T) redisTemplate.opsForValue().get(key);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        // Remove the authorized client
        String key = generateKey(clientRegistrationId, principalName);
        redisTemplate.delete(key);
    }

    private String generateKey(String clientRegistrationId, String principalName) {
        return clientRegistrationId + ":" + principalName;
    }
}
