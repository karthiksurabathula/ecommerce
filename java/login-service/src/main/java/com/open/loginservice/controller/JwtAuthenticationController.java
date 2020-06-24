package com.open.loginservice.controller;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.open.loginservice.model.JwtRequest;
import com.open.loginservice.model.ResetPasswordRequest;
import com.open.loginservice.service.JwtService;

@RestController
@CrossOrigin
@RequestMapping("login-service/")
public class JwtAuthenticationController {

	@Autowired
	private JwtService jwtService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	@ResponseBody
	public ResponseEntity<?> authenticate(@RequestBody JwtRequest authenticationRequest, HttpServletResponse responseMap) {
		return jwtService.authorize(authenticationRequest, responseMap);
	}

	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public ResponseEntity<?> register(@RequestBody JwtRequest user, HttpServletResponse responseMap) {
		return jwtService.save(user, responseMap);
	}
	
	@RequestMapping(value = "/check", method = RequestMethod.POST)
	public ResponseEntity<?> register(@RequestParam String username) {
		return jwtService.checkUsername(username);
	}
	
	@RequestMapping(value = "/api/logout", method = RequestMethod.POST)
	public ResponseEntity<?> resetPassword() {
		return jwtService.logout();
	}
	
	@RequestMapping(value = "/api/reset", method = RequestMethod.POST)
	public ResponseEntity<?> resetPasswordLoggedIn(@RequestBody ResetPasswordRequest resetReq, HttpServletResponse responseMap) {
		return jwtService.resetPasswordLoggedIn(resetReq, responseMap);
	}

	//
	@RequestMapping(value = "/reset", method = RequestMethod.POST)
	public ResponseEntity<?> resetPassword(@RequestBody JwtRequest resetReq, HttpServletResponse responseMap) {
		return jwtService.resetPassword(resetReq, responseMap);
	}
	
	@RequestMapping(value = "/api/authorize", method = RequestMethod.GET)
	public Authentication checkUserAuthenication() {
		return jwtService.checkUserAuthentication();
	}

}