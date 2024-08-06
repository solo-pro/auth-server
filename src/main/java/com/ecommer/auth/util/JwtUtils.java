package com.ecommer.auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;


@Component
public class JwtUtils {
    private final String accessTokenName;
    private final Algorithm accessTokenSecret;
    public final Long accessTokenExpiration;

    private final String refreshTokenName;
    private final Algorithm refreshTokenSecret;
    private final Long refreshTokenExpiration;



    public String generateToken(UserDetails user) {

        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpiration))
                .sign(accessTokenSecret);
    }
    public String generateRefreshToken(UserDetails user) {
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                .sign(refreshTokenSecret);
    }
    public String parseToken(String token) {
        return JWT.require(accessTokenSecret)
                .build()
                .verify(token)
                .getSubject();

    }

    public boolean validateToken(String authToken) {
        try {
            JWT.require(accessTokenSecret)
                    .build()
                    .verify(authToken);
            return true;
        } catch (JWTVerificationException ex) {
            // Log exception details
            return false;
        }
    }
    public void setCookieToTokens(HttpServletResponse response, String refreshToken, String accessToken) {
        ResponseCookie refreshTokenCookie = ResponseCookie.from(refreshTokenName, refreshToken)
                .maxAge(refreshTokenExpiration.intValue())
                .httpOnly(true)
                .path("/")
                .build();
        ResponseCookie accessTokenCookie = ResponseCookie.from(accessTokenName, accessToken)
                .maxAge(accessTokenExpiration.intValue())
                .httpOnly(true)
                .path("/")
                .build();

        response.addHeader("Set-Cookie", refreshTokenCookie.toString());
        response.addHeader("Set-Cookie", accessTokenCookie.toString());
    }


    public JwtUtils(
            @Value("${jwt.access-token.name}") String accessTokenName,
            @Value("${jwt.access-token.secret}") String accessTokenSecret,
            @Value("${jwt.access-token.expiration}") Long accessTokenExpiration,
            @Value("${jwt.refresh-token.name}") String refreshTokenName,
            @Value("${jwt.refresh-token.secret}") String refreshTokenSecret,
            @Value("${jwt.refresh-token.expiration}") Long refreshTokenExpiration) {

        this.accessTokenName = accessTokenName;
        this.accessTokenSecret = Algorithm.HMAC512(accessTokenSecret);
        this.accessTokenExpiration = accessTokenExpiration;
        this.refreshTokenName = refreshTokenName;
        this.refreshTokenSecret = Algorithm.HMAC512(refreshTokenSecret);
        this.refreshTokenExpiration = refreshTokenExpiration;
    }
}
