package com.ecommer.auth.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;


public interface AuthService extends AuthenticationSuccessHandler, UserDetailsService, AuthenticationFailureHandler {
}
