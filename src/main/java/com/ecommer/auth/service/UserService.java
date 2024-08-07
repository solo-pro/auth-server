package com.ecommer.auth.service;

import com.ecommer.auth.dto.response.TokenResponse;
import com.ecommer.auth.entity.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface UserService  {
    User saveFromOAuthUser(OAuth2User oAuth2User);
    User loadUserByUsername(String username);
    User update(OAuth2User oauth2User, String phoneNumber, String address);
    TokenResponse successLogin(OAuth2User oauth2User);
}
