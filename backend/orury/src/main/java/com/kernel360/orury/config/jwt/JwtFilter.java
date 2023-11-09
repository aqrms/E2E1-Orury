package com.kernel360.orury.config.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
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

import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@Component
public class JwtFilter extends OncePerRequestFilter {

	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String REFRESHTOKEN_HEADER = "Refresh-Token";
	private TokenProvider tokenProvider;

	public JwtFilter(TokenProvider tokenProvider) {
		this.tokenProvider = tokenProvider;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		try {
			String accessToken = resolveToken(request, AUTHORIZATION_HEADER);
			Authentication authentication = tokenProvider.getAuthentication(accessToken);
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} catch (ExpiredJwtException e) {
			reissueAccessToken(request, response, e);
		} catch (Exception e) {
			request.setAttribute("exception", e);
		}

		filterChain.doFilter(request, response);
	}

	//리퀘스트 헤더에서 토큰 정보를 꺼내온다
	private String resolveToken(HttpServletRequest request, String headerName) {

		String bearerToken = request.getHeader(headerName);

		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7);
		}

		return null;
	}

	private void reissueAccessToken(HttpServletRequest request, HttpServletResponse response, Exception exception) {
		try {
			String refreshToken = resolveToken(request, REFRESHTOKEN_HEADER);
			String oldAccessToken = resolveToken(request, AUTHORIZATION_HEADER);

			if (StringUtils.hasText(refreshToken) && tokenProvider.validateToken(refreshToken)) {
				createNewAccessTokenAndAuthenticate(response, oldAccessToken);
			} else {
				throw exception;
			}
		} catch (Exception e) {
			request.setAttribute("exception", e);
		}
	}

	private void createNewAccessTokenAndAuthenticate(HttpServletResponse response, String oldAccessToken) throws
		JsonProcessingException {
		String newAccessToken = tokenProvider.recreateAccessToken(oldAccessToken);
		Authentication authentication = tokenProvider.getAuthentication(newAccessToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		response.setHeader("New-Access-Token", newAccessToken);
	}
}
