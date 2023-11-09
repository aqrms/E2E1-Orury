package com.kernel360.orury.config;

import com.kernel360.orury.config.jwt.JwtAuthenticationEntryPoint;
import com.kernel360.orury.config.jwt.JwtAccessDeniedHandler;
import com.kernel360.orury.config.jwt.JwtFilter;
import com.kernel360.orury.config.jwt.TokenProvider;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

import lombok.RequiredArgsConstructor;

/**
 author : aqrms
 date : 2023/11/2
 description : @EnableMethodSecurity는 추후 컨트롤러에서 API메서드 단위로 권한을 적용(@PreAuthorize)하기 위함
 */
@EnableMethodSecurity
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {
	private final JwtFilter jwtFilter;
	private final AuthenticationEntryPoint entryPoint;

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
			.csrf().disable()
			.headers(headers -> headers.frameOptions().sameOrigin())
			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
				.antMatchers("/api/auth/authenticate", "/api/user/signup").permitAll()
				.anyRequest().authenticated()
			)
			.sessionManagement(sessionManagement ->
				sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			.addFilterBefore(jwtFilter, BasicAuthenticationFilter.class)
			.exceptionHandling(handler -> handler.authenticationEntryPoint(entryPoint))
			.build();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
