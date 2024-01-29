package com.aliens.IdentityManagement;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@SpringBootApplication
@EnableMongoRepositories
public class IdentityManagementApplication {

	public static void main(String[] args) {
		SpringApplication.run(IdentityManagementApplication.class, args);
	}

}

