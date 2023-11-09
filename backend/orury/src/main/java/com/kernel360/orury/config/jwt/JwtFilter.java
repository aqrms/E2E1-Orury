package com.kernel360.orury.config.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

	private final TokenProvider tokenProvider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		try {
			String accessToken = parseBearerToken(request, HttpHeaders.AUTHORIZATION);
			User user = parseUserSpecification(accessToken);
			AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user,
				accessToken, user.getAuthorities());
			authenticated.setDetails(new WebAuthenticationDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authenticated);
		} catch (ExpiredJwtException e) {
			reissueAccessToken(request, response, e);
		} catch (Exception e) {
			request.setAttribute("exception", e);
		}

		filterChain.doFilter(request, response);
	}

	private String parseBearerToken(HttpServletRequest request, String headerName) {
		return Optional.ofNullable(request.getHeader(headerName))
			.filter(token -> token.substring(0, 7).equalsIgnoreCase("Bearer "))
			.map(token -> token.substring(7))
			.orElse(null);
	}

	private User parseUserSpecification(String token) {
		String[] split = Optional.ofNullable(token)
			.filter(subject -> subject.length() >= 10)
			.map(tokenProvider::validateTokenAndGetSubject)
			.orElse("anonymous:anonymous")
			.split(":");

		return new User(split[0], "", List.of(new SimpleGrantedAuthority(split[1])));
	}

	private void reissueAccessToken(HttpServletRequest request, HttpServletResponse response, Exception exception) {
		try {
			String refreshToken = parseBearerToken(request, "Refresh-Token");
			if (refreshToken == null) {
				throw exception;
			}
			String oldAccessToken = parseBearerToken(request, HttpHeaders.AUTHORIZATION);
			tokenProvider.validateRefreshToken(refreshToken, oldAccessToken);
			String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
			User user = parseUserSpecification(newAccessToken);
			AbstractAuthenticationToken authenticated = UsernamePasswordAuthenticationToken.authenticated(user,
				newAccessToken, user.getAuthorities());
			authenticated.setDetails(new WebAuthenticationDetails(request));
			SecurityContextHolder.getContext().setAuthentication(authenticated);

			response.setHeader("New-Access-Token", newAccessToken);
		} catch (Exception e) {
			request.setAttribute("exception", e);
		}
	}
}
