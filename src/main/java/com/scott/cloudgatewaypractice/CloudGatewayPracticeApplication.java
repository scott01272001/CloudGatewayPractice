package com.scott.cloudgatewaypractice;

import com.scott.cloudgatewaypractice.dao.User;
import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class CloudGatewayPracticeApplication {

    @Autowired
    private PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(CloudGatewayPracticeApplication.class, args);
    }

    @Bean
    public CommandLineRunner runner(UserRepository userRepository) {
        return args -> {
            User user1 = User.builder()
                    .firstName("scott")
                    .lastName("chiang")
                    .email("scott@gmail.com")
                    .password(passwordEncoder.encode("asd123"))
                    .build();
            userRepository.save(user1);

            User user2 = User.builder()
                    .firstName("john")
                    .lastName("kelly")
                    .email("john@gmail.com")
                    .password("qweqwe")
                    .build();
            userRepository.save(user2);
        };
    }
}
