package com.meteoauth.MeteoAuth.assembler;

import com.meteoauth.MeteoAuth.dto.UserDtoRequest;
import com.meteoauth.MeteoAuth.dto.UserDtoResponse;
import com.meteoauth.MeteoAuth.entities.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class UserAssembler {
    private final PasswordEncoder passwordEncoder;

    public UserAssembler() {
        this.passwordEncoder = new BCryptPasswordEncoder(11);
    }

    public UserDtoResponse getUserDtoResponse(User user) {
        UserDtoResponse userDtoResponse = new UserDtoResponse();
        userDtoResponse.setUsername(user.getUsername());
        userDtoResponse.setEmail(user.getEmail());
        userDtoResponse.setCity(user.getCity());
        return userDtoResponse;
    }

    public User getUser(UserDtoRequest userDtoRequest) {
        User user = new User();
        user.setUsername(userDtoRequest.getUsername());
        user.setPassword(passwordEncoder.encode(userDtoRequest.getPassword()));
        user.setEmail(userDtoRequest.getEmail());
        user.setCity(userDtoRequest.getCity());
        return user;
    }

    public List<UserDtoResponse> getUserDtoRequestList(Iterable<User> userList) {
        List<UserDtoResponse> userDtoResponseList = new ArrayList<>();
        for (User user : userList) {
            UserDtoResponse temp = new UserDtoResponse();
            temp.setUsername(user.getUsername());
            temp.setEmail(user.getEmail());
            temp.setCity(user.getCity());
            userDtoResponseList.add(temp);
        }
        return userDtoResponseList;
    }
}