package com.example.memo.configuration.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;


class JwtAuthorizationFilter extends OncePerRequestFilter {





	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {
		String token = JwtUtil.getTokenFromHeader(request);

		if(!JwtUtil.validateToken(token)){
			Authentication authentication = JwtUtil.getAuthentication(token);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			return;
		}


		// TODO : 요청에 들어온 JWT를 parsing해서 "ROLE_MEMBER" 권한이 있는지 확인하고, SecurityContextHolder에 context 설정하기
		filterChain.doFilter(request, response);
	}


}
