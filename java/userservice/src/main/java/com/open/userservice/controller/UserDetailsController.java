package com.open.userservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.open.userservice.entity.UserDetails;
import com.open.userservice.service.UserDetailsService;

@RestController
public class UserDetailsController {

	@Autowired
	private UserDetailsService userDetailsService;

	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> register(@RequestBody UserDetails userDetails) {
		return userDetailsService.createUserDetails(userDetails);
	}

	@RequestMapping(value = "/user-details", method = RequestMethod.GET)
	public ResponseEntity<?> getUser(@RequestParam String username) {
		return userDetailsService.getUserDetails(username);
	}
}
