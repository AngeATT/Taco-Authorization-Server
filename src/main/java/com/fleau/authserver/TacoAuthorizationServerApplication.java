package com.fleau.authserver;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class TacoAuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(TacoAuthorizationServerApplication.class, args);
	}

}
