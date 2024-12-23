package com.es.jwtsecurity;

import com.es.jwtsecurity.security.RsaKeyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyProperties.class)
public class JwtSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtSecurityApplication.class, args);
    }

}
