package com.labzang.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

@Configuration
public class SwaggerUiConfig {

	@Bean
	public RouterFunction<ServerResponse> swaggerUiRouterFunction() {
		return RouterFunctions.route(
				GET("/docs"),
				request -> ServerResponse.temporaryRedirect(
						java.net.URI.create("/swagger-ui.html")
				).build()
		);
	}
}

