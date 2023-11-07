package com.kernel360.orury.domain.user.controller;

import static org.springframework.data.util.Optionals.*;

import javax.validation.Valid;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.kernel360.orury.config.jwt.JwtFilter;
import com.kernel360.orury.config.jwt.TokenProvider;
import com.kernel360.orury.domain.user.db.RefreshTokenEntity;
import com.kernel360.orury.domain.user.db.RefreshTokenRepository;
import com.kernel360.orury.domain.user.db.UserEntity;
import com.kernel360.orury.domain.user.db.UserRepository;
import com.kernel360.orury.domain.user.exception.NotFoundMemberException;
import com.kernel360.orury.domain.user.model.LoginDto;
import com.kernel360.orury.domain.user.model.TokenDto;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	private final TokenProvider tokenProvider;
	private final AuthenticationManagerBuilder authenticationManagerBuilder;
	private final RefreshTokenRepository refreshTokenRepository;
	private final UserRepository userRepository;

	@PostMapping("/authenticate")
	public ResponseEntity<TokenDto> authenticate(@Valid @RequestBody LoginDto loginDto) {

		UsernamePasswordAuthenticationToken authenticationToken =
			new UsernamePasswordAuthenticationToken(loginDto.getEmailAddr(), loginDto.getPassword());

		Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		String accessToken = tokenProvider.createAccessToken(authentication);
		String refreshToken = tokenProvider.createRefreshToken();

		UserEntity userEntity = userRepository.findByEmailAddr(authentication.getName())
			.orElseThrow(() -> new NotFoundMemberException("User not found with email: " + authentication.getName()));

		refreshTokenRepository.findById(userEntity.getId())
			.ifPresentOrElse(
				it -> it.updateRefreshToken(refreshToken),
				() -> refreshTokenRepository.save(new RefreshTokenEntity(userEntity, refreshToken))
			);

		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setContentType(MediaType.APPLICATION_JSON);

		return new ResponseEntity<>(new TokenDto(accessToken, refreshToken), httpHeaders, HttpStatus.OK);
	}
}

