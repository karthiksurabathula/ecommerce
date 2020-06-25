package com.open.loginservice.service;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.open.loginservice.model.userdetails.UserDetails;
import com.open.loginservice.model.userdetails.UserDetailsResponse;

@Service
public class OutboundService {

	@Value("${userService.url}")
	private String userService_url;
	@Value("${userService.connectionTimeout}")
	private int userService_connectionTimeout;
	@Value("${userService.readTimeout}")
	private int userService_readTimeout;

	public ResponseEntity<UserDetailsResponse> createUserDetails(String username, String email) {
		UserDetails user = new UserDetails();
		user.setEmail(email);
		user.setUsername(username);
		RestTemplate restTemplate = new RestTemplateBuilder().setConnectTimeout(Duration.ofMillis(userService_connectionTimeout))
				.setReadTimeout(Duration.ofMillis(userService_readTimeout)).build();
		return restTemplate.postForEntity(userService_url + "register", user, UserDetailsResponse.class);
	}

	public ResponseEntity<UserDetailsResponse> getUserDetails(String username) {
		RestTemplate restTemplate = new RestTemplateBuilder().setConnectTimeout(Duration.ofMillis(userService_connectionTimeout))
				.setReadTimeout(Duration.ofMillis(userService_readTimeout)).build();
		 return restTemplate.getForEntity(userService_url + "user-details?username=" + username, UserDetailsResponse.class);
	}
}
