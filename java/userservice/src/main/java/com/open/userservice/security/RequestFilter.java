package com.open.userservice.security;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.open.userservice.security.model.User;
import com.open.userservice.security.service.AuthenticationCheckImpl;

import io.jsonwebtoken.ExpiredJwtException;

@Component
public class RequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private AuthenticationCheckImpl authCheck;

	private static final Logger log = LogManager.getLogger(RequestFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		try {

			final String requestTokenHeader = request.getHeader("Authorization");
			String username = null;
			String jwtToken = null;

			// JWT Token is in the form "Bearer token". Remove Bearer word and get only the
			// Token
			if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
				jwtToken = requestTokenHeader.substring(7);
				try {
					username = jwtTokenUtil.getUsernameFromToken(jwtToken);
				} catch (IllegalArgumentException e) {
					System.out.println(username + ":Unable to get JWT Token");
				} catch (ExpiredJwtException e) {
					System.out.println(username + ": JWT Token has expired");
				} catch (io.jsonwebtoken.SignatureException e) {
					System.out.println(username + ":JWT Signature Not Valid");
				} catch (Exception e) {
					System.out.println(username + ":Unknown JWT Exception Occured");
					e.printStackTrace();
				}
			} else {
				logger.warn("Invalid Token: " + requestTokenHeader);
			}

			// Validate Token
			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				final User user = authCheck.getUser(username);
				if (user != null) {
					final UserDetails userDetails = new CustomUserDetails(user);
					Date jwtTokenUt = jwtTokenUtil.getExpirationDateFromToken(jwtToken);
					if (user.getToken().equals(jwtToken) && new Date().before(jwtTokenUt)) {
						UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
								userDetails, null, userDetails.getAuthorities());
						usernamePasswordAuthenticationToken
								.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
						SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
					}
				}
			}
			chain.doFilter(request, response);
		} catch (Exception e) {
			log.error("", e);
		}
	}

}
