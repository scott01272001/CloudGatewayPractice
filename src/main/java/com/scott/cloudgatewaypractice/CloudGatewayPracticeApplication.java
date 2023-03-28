package com.scott.cloudgatewaypractice;

import com.scott.cloudgatewaypractice.dao.User;
import com.scott.cloudgatewaypractice.dao.repo.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class CloudGatewayPracticeApplication {

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
                    .password("asd123")
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
