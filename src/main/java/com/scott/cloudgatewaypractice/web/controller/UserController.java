package com.scott.cloudgatewaypractice.web.controller;

import com.scott.cloudgatewaypractice.dao.User;
import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping(value = "/api/users")
@AllArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping(value = "")
    public List<User> findAll() {
//        HttpHeaders headers = request.headers().asHttpHeaders();
//        headers.forEach((name, values) -> {
//            System.out.println(name + ": " + values);
//        });

        return userRepository.findAll();
    }

}
