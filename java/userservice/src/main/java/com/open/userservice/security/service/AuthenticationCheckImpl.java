package com.open.userservice.security.service;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.open.userservice.security.model.LoginResponse;
import com.open.userservice.security.model.User;

@Service
public class AuthenticationCheckImpl {
	
	@Value("${auth.url}")
	private String url;
	@Value("${auth.connectionTimeout}")
	private int connectionTimeout;
	@Value("${auth.readTimeout}")
	private int readTimeout;
	
	public User getUser(String username) {
		RestTemplate restTemplate = new RestTemplateBuilder().setConnectTimeout(Duration.ofMillis(connectionTimeout)).setReadTimeout(Duration.ofMillis(readTimeout)).build();
		ResponseEntity<LoginResponse> loginUser = restTemplate.getForEntity(url + "?username=" + username, LoginResponse.class);
		return loginUser.getBody().getUser();
	}
}
