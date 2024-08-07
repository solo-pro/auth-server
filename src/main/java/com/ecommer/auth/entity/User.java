package com.ecommer.auth.entity;

import com.ecommer.auth.config.BaseTimeEntity;
import com.ecommer.auth.dto.response.TokenResponse;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Entity
@Table(name = "USERS",
        indexes = {
        @Index(name = "USER_EMAIL_IDX",columnList = "EMAIL", unique = true),
        @Index(name = "USER_USERNAME_IDX",columnList = "USERNAME", unique = true)
})
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class User extends BaseTimeEntity implements UserDetails {
    @Id @GeneratedValue
    @Column(name = "USER_ID")
    private Long id;
    @Column(name = "EMAIL", nullable = false, unique = true)
    private String email;
    @Column(name = "USERNAME", nullable = false)
    private String username;
    @Column(name = "NICKNAME")
    private String nickname;
    @Column(name = "PROVIDER", nullable = false)
    private String provider;
    @Builder.Default
    @Column(name = "ROLE", nullable = false)
    private String role = "ROLE_USER";
    @Column(name = "PROFILE_IMAGE_URL", length = 1000)
    private String profileImageUrl;
    @Column(name = "PHONE_NUMBER", nullable = false, length = 20)
    private String phoneNumber;
    @Column(name = "ADDRESS", nullable = false, length = 1000)
    private String address;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(()-> role);
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
    public static User from(OAuth2User oAuth2User){
        Map<String, Object> kakaoAccount = oAuth2User.getAttribute("kakao_account");
        if(Objects.isNull(kakaoAccount)){
            return User.builder()
                    .email(oAuth2User.getAttribute("email"))
                    .nickname(oAuth2User.getAttribute("name"))
                    .username(oAuth2User.getName())
                    .profileImageUrl(oAuth2User.getAttribute("picture"))
                    .provider("google")
                    .build();
        }

        Map<String, String> properties = oAuth2User.getAttribute("properties");
        assert properties != null;
        return User.builder()
                .email((String) kakaoAccount.get("email"))
                .nickname(properties.get("nickname"))
                .username(oAuth2User.getName())
                .profileImageUrl(properties.get("profile_image"))
                .provider("kakao")
                .build();
    }
    public void firstLogin(String phoneNumber, String address){
        this.phoneNumber = phoneNumber;
        this.address = address;
    }
}
