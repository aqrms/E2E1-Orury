package com.kernel360.orury.config.jwt;

import com.kernel360.orury.domain.user.service.CustomUserDetails;
import com.kernel360.orury.global.message.errors.ErrorMessages;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

	private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
	private static final String AUTHORITIES_KEY = "auth";
	private static final String USER_ID_KEY = "id";
	private final String secret;
	private final long expirationMinutes;
	private final long refreshExpirationHours;

	private Key key;

	public TokenProvider(
		@Value("${jwt.secret}") String secret,
		@Value("${jwt.expiration-minutes}") long expirationMinutes,
		@Value("${jwt.refresh-expiration-hours}") long refreshExpirationHours
	) {
		this.secret = secret;
		this.expirationMinutes = expirationMinutes;
		this.refreshExpirationHours = refreshExpirationHours;
	}

	// 빈이 생성되고 생성자에서 주입받은 jwt 시크릿 키를 base65 디코드해서 key 변수에 할당
	@Override
	public void afterPropertiesSet() {
		byte[] keyBytes = Decoders.BASE64.decode(secret);
		this.key = Keys.hmacShaKeyFor(keyBytes);
	}

	// Authentication을 파라미터로 받아서 권한들을 가져온다, yml 파일에 설정한 만료시간을 설정하고 토큰을 생성한다
	public String createAccessToken(Authentication authentication) {
		String authorities = authentication.getAuthorities().stream()
			.map(GrantedAuthority::getAuthority)
			.collect(Collectors.joining(","));

		long now = (new Date()).getTime();
		Date validity = new Date(now + this.expirationMinutes);

		CustomUserDetails principal = (CustomUserDetails)authentication.getPrincipal();
		Long userId = principal.getId();

		return Jwts.builder()
			.setSubject(authentication.getName())
			.claim(AUTHORITIES_KEY, authorities)
			.claim(USER_ID_KEY, userId)
			.signWith(key, SignatureAlgorithm.HS512)
			.setExpiration(validity)
			.compact();
	}

	public String createRefreshToken(Authentication authentication) {
		CustomUserDetails principal = (CustomUserDetails)authentication.getPrincipal();
		Long userId = principal.getId();

		long now = (new Date()).getTime();
		Date validity = new Date(now + this.refreshExpirationHours);

		return Jwts.builder()
			.setSubject(userId.toString())  // 사용자 아이디를 서브젝트로 설정
			.signWith(key, SignatureAlgorithm.HS512)
			.setExpiration(validity)
			.compact();
	}

	// 토큰을 파라미터로 받아서 클레임을 만들고 이를 이용해 유저 객체를 만들고 Authentication 객체 리턴
	public Authentication getAuthentication(String token) {
		Claims claims = Jwts
			.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();

		Collection<? extends GrantedAuthority> authorities =
			Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		User principal = new User(claims.getSubject(), "", authorities);

		return new UsernamePasswordAuthenticationToken(principal, token, authorities);
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
			return true;
		} catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
			logger.info(ErrorMessages.MALFORMED_JWT.getMessage());
		} catch (ExpiredJwtException e) {
			logger.info(ErrorMessages.EXPIRED_JWT.getMessage());
		} catch (UnsupportedJwtException e) {
			logger.info(ErrorMessages.UNSUPPORTED_JWT.getMessage());
		} catch (IllegalArgumentException e) {
			logger.info(ErrorMessages.ILLEGAL_ARGUMENT_JWT.getMessage());
		}
		return false;
	}

}