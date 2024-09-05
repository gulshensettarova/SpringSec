package test.example.SpringSec;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"security", "security.jwt","service","model"})
public class SpringSecApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecApplication.class, args);
	}

}
