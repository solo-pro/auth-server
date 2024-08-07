package com.ecommer.auth.controller;

import com.ecommer.auth.dto.response.TokenResponse;
import com.ecommer.auth.entity.User;
import com.ecommer.auth.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    @GetMapping("/login")
    public String hello() {
        return "login";
    }
    @GetMapping("/additional-info")
    public String showAdditionalInfoForm(@AuthenticationPrincipal OAuth2User oauth2User, Model model) {
        // 현재 사용자 정보 가져오기
        User user = userService.loadUserByUsername(oauth2User.getName());
        if(user.getAddress()!=null && user.getPhoneNumber()!=null){
            return "redirect:success";
        }
        model.addAttribute("user", user);
        return "additional-info";
    }
    @PostMapping("/additional-info")
    public String submitAdditionalInfo(
            @AuthenticationPrincipal OAuth2User oauth2User,
            @RequestParam String phoneNumber,
            @RequestParam String address) {
        // 사용자 정보 업데이트
        userService.update(oauth2User, phoneNumber, address);
        return "redirect:success";  // 홈 페이지로 리디렉션
    }
    @GetMapping("/success")
    public void success(@AuthenticationPrincipal OAuth2User oauth2User, HttpServletResponse response) throws IOException {
        TokenResponse tokenResponse = userService.successLogin(oauth2User);
        response.sendRedirect("/success?token="+tokenResponse.accessToken());

    }
}
