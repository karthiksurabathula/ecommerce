package com.open.userservice.service;

import java.util.HashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.open.userservice.entity.UserDetails;
import com.open.userservice.repository.UserDetailsRepository;

@Service
public class UserDetailsService {

	@Autowired
	private UserDetailsRepository userRepo;

	private static final Logger log = LogManager.getLogger(UserDetailsService.class);

	public ResponseEntity<?> createUserDetails(UserDetails user) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			UserDetails userNew = new UserDetails();
			userNew.setEmail(user.getEmail());
			userNew.setUsername(user.getUsername());
			response.put("userDetails", userRepo.saveAndFlush(userNew));
			response.put("indicator", "success");
			response.put("message", "User details created successfully");
			return new ResponseEntity<>(response, HttpStatus.OK);
		} catch (Exception e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Error Occured, if issue persists please contact administrator";
		}

		if (message != null)
			response.put("message", message);

		return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
	}

	public ResponseEntity<?> getUserDetails(String username) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			UserDetails user = userRepo.findByUsername(username);
			if (user != null) {
				response.put("userDetails", user);
				response.put("indicator", "success");
				return new ResponseEntity<>(response, HttpStatus.OK);
			} else {
				response.put("indicator", "fail");
				response.put("message", "User details not found");
				return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
			}
		} catch (Exception e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Error Occured, if issue persists please contact administrator";
		}

		if (message != null)
			response.put("message", message);

		return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
	}

}
