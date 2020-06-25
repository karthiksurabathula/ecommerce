package com.open.userservice.security.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.open.userservice.security.CustomUserDetails;

@Configuration
public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private AuthenticationCheckImpl authCheck;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		CustomUserDetails user = new CustomUserDetails(authCheck.getUser(username));
		return user;
	}

}
