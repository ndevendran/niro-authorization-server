package authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;

@SpringBootApplication
public class NiroAuthorizationServerApplication {
	public static void main(String[] args) {
		SpringApplication.run(NiroAuthorizationServerApplication.class, args);
	}
}
