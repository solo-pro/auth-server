package com.ecommer.auth.service;


import com.ecommer.auth.dto.response.TokenResponse;
import com.ecommer.auth.entity.User;
import com.ecommer.auth.repository.UserRepository;
import com.ecommer.auth.util.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, AuthService {

    private final JwtUtils jwtUtils;
    private final UserRepository userRepository;


    @Override
    public User loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("loadUserByUsername : {}",username);
        return userRepository.findByUsername(username);
    }
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        log.info("onAuthenticationFailure : {}",exception.getMessage());
        response.sendRedirect("/login");
    }

    @Override
    @Transactional
    public User update(OAuth2User oauth2User, String phoneNumber, String address) {
        log.info("update : {}",oauth2User);
        User user = loadUserByUsername(oauth2User.getName());
        user.firstLogin(phoneNumber, address);
        return user;
    }

    @Override
    @Transactional
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2User principal = (OAuth2User) authentication.getPrincipal();
        log.info("{} is login {}", principal.getName(), principal.getAttributes());
        saveFromOAuthUser(principal);
        response.sendRedirect("/additional-info");
    }

    @Override
    public User saveFromOAuthUser(OAuth2User oAuth2User) {
        User user = loadUserByUsername(oAuth2User.getName());
        if(user!=null) {
            log.info("user is already exist : {}",user);
            return user;
        }
        log.info("saveFromOAuthUser : {}",oAuth2User);
        user = User.from(oAuth2User);
        return userRepository.save(user);

    }

    @Override
    public TokenResponse successLogin(OAuth2User oauth2User) {
        log.info("successLogin : {}",oauth2User);
        User user = loadUserByUsername(oauth2User.getName());
        String accessToken = jwtUtils.generateToken(user);
        String refreshToken = jwtUtils.generateRefreshToken(user);
        return new TokenResponse(accessToken,"Bearer", refreshToken,  jwtUtils.accessTokenExpiration);

    }
}
