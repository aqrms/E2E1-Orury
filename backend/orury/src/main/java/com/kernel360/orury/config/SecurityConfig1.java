package com.kernel360.orury.config;
//
// import com.kernel360.orury.config.jwt.JwtAuthenticationEntryPoint;
// import com.kernel360.orury.config.jwt.JwtAccessDeniedHandler;
// import com.kernel360.orury.config.jwt.JwtFilter;
// import com.kernel360.orury.config.jwt.TokenProvider;
//
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
// import org.springframework.web.filter.CorsFilter;
//
// import java.util.List;
//
// /**
//  author : aqrms
//  date : 2023/11/2
//  description : @EnableMethodSecurity는 추후 컨트롤러에서 API메서드 단위로 권한을 적용(@PreAuthorize)하기 위함
//  */
// @EnableMethodSecurity(prePostEnabled = true)
// @Configuration
// public class SecurityConfig {
//
// 	private static final List<String> SWAGGER = List.of(
// 		"/swagger-ui.html",
// 		"/swagger-ui/**",
// 		"/v3/api-docs/**"
// 	);
// 	private final TokenProvider tokenProvider;
// 	private final CorsFilter corsFilter;
// 	private final AuthenticationEntryPoint entryPoint;
// 	private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
// 	private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
// 	private final JwtFilter jwtFilter;
//
// 	public SecurityConfig(
// 		TokenProvider tokenProvider,
// 		CorsFilter corsFilter,
// 		AuthenticationEntryPoint entryPoint, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
// 		JwtAccessDeniedHandler jwtAccessDeniedHandler,
// 		JwtFilter jwtFilter) {
// 		this.tokenProvider = tokenProvider;
// 		this.corsFilter = corsFilter;
// 		this.entryPoint = entryPoint;
// 		this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
// 		this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
// 		this.jwtFilter = jwtFilter;
// 	}
//
// 	@Bean
// 	public PasswordEncoder passwordEncoder() {
// 		return new BCryptPasswordEncoder();
// 	}
//
// 	@Bean
// 	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
// 		http
// 			// token을 사용하는 방식이기 때문에 csrf를 disable합니다.
// 			.csrf(csrf -> csrf.disable())
//
// 			.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
// 			.exceptionHandling(handler -> handler.authenticationEntryPoint(entryPoint)
// 			)
//
// 			.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
// 				.mvcMatchers(SWAGGER.toArray(new String[0])).permitAll()
// 				.antMatchers("/api/hello", "/api/auth/authenticate", "/api/user/signup").permitAll()
// 				.anyRequest().authenticated()
// 			)
//
// 			// 세션을 사용하지 않기 때문에 STATELESS로 설정
// 			.sessionManagement(sessionManagement ->
// 				sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
// 			)
// 			// JWT필터 적용
// 			.addFilterBefore(jwtFilter, BasicAuthenticationFilter.class)
// 		return http.build();
// 	}
// }