package com.scott.cloudgatewaypractice.web.controller;

import com.scott.cloudgatewaypractice.dao.User;
import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping(value = "/api/users")
@AllArgsConstructor
//@PreAuthorize("isAuthenticated()")
public class UserController {

    private final UserRepository userRepository;

    @GetMapping(value = "")
    public List<User> findAll(Authentication auth) {
        System.out.println("is aurh: " + auth.isAuthenticated());
        return userRepository.findAll();
    }

}
