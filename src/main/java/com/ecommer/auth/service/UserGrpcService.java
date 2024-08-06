package com.ecommer.auth.service;

import com.ecommer.auth.entity.User;
import com.ecommer.auth.repository.UserRepository;
import com.ecommer.auth.util.JwtUtils;
import io.ecommer.grpc.TokenRequest;
import io.ecommer.grpc.UserGrpc;
import io.ecommer.grpc.UserResponse;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;

@Slf4j
@GrpcService
@RequiredArgsConstructor
public class UserGrpcService extends UserGrpc.UserImplBase{
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    @Override
    public void getUser(TokenRequest request, StreamObserver<UserResponse> responseObserver) {
        try {
            log.info("getUser : {}",request);
            String token = request.getToken();
            String username = jwtUtils.parseToken(token);
            User user = userRepository.findByUsername(username);
            UserResponse userResponse = UserResponse.newBuilder()
                    .setId(user.getId().intValue())
                    .setUsername(user.getUsername())
                    .setPhone(user.getPhoneNumber())
                    .setAddress(user.getAddress())
                    .setEmail(user.getEmail())
                    .setProfile(user.getProfileImageUrl())
                    .build();
            responseObserver.onNext(userResponse);
            responseObserver.onCompleted();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
