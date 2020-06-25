package com.open.loginservice.service;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import javax.security.auth.login.AccountExpiredException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.open.loginservice.entity.LoginUser;
import com.open.loginservice.model.JwtRequest;
import com.open.loginservice.model.ResetPasswordRequest;
import com.open.loginservice.model.UserSettingRequest;
import com.open.loginservice.model.userdetails.UserDetailsResponse;
import com.open.loginservice.repository.LoginUserRepository;
import com.open.loginservice.security.CustomUserDetails;
import com.open.loginservice.security.JwtTokenUtil;

@Service
public class JwtService {

	@Autowired
	private LoginUserRepository loginUser;
	@Autowired
	private PasswordEncoder bcryptEncoder;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtTokenUtil jwtTokenUtil;
	@Autowired
	private OutboundService outbound;

	private static final Logger log = LogManager.getLogger(JwtService.class);

	@Value("${jwt.timeseconds}")
	private int timeseconds;

	public ResponseEntity<?> save(JwtRequest user, HttpServletResponse responseMap) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			if (user.getUsername().length() > 1) {
				final LoginUser user1 = loginUser.findByUsername(user.getUsername());
				if (user1 == null) {
					ResponseEntity<UserDetailsResponse> res = outbound.createUserDetails(user.getUsername(),
							user.getEmail());
					if (res.getStatusCode().value() == 200) {
						createUser(user.getUsername(), user.getPassword(), user.getRole(), false, 0);
					}
					response.put("indicator", "success");
					response.put("message", "User created successfully");
					return new ResponseEntity<>(response, HttpStatus.OK);
				} else {
					response.put("indicator", "success");
					response.put("message", "User already exists");
					return new ResponseEntity<>(response, HttpStatus.OK);
				}
			} else {
				response.put("indicator", "fail");
				response.put("message", "Username cannot be empty");
				log.info("Token Not Found");
				return new ResponseEntity<>(response, HttpStatus.OK);
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

	public ResponseEntity<?> resetPassword(JwtRequest passwordReq, HttpServletResponse responseMap) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			ResponseEntity<UserDetailsResponse> res = outbound.getUserDetails(passwordReq.getUsername());
			if (res.getStatusCode().value() == 200) {
				if (res.getBody().getUserDetails().getEmail().equals(passwordReq.getEmail())) {
					final LoginUser user1 = loginUser.findByUsername(passwordReq.getUsername());
					if (user1 != null) {
						user1.setPassword(bcryptEncoder.encode("1234"));
						user1.setFailurecount(0);
						user1.setResetPassword(false);
						loginUser.saveAndFlush(user1);
						response.put("indicator", "success");
						response.put("message", "If user exists password will be sent to Mail registered");
						return new ResponseEntity<>(response, HttpStatus.OK);
					} else {
						response.put("indicator", "success");
						response.put("message", "If user exists password will be sent to Mail registered");
						log.warn("Userid not found in Login Users table" + passwordReq.getUsername());
						return new ResponseEntity<>(response, HttpStatus.OK);
					}
				} else {
					response.put("indicator", "success");
					response.put("message", "If user exists password will be sent to Mail registered");
					log.warn("Email did not match with User Id: " + passwordReq.getUsername());
					return new ResponseEntity<>(response, HttpStatus.OK);
				}
			} else {
				response.put("indicator", "fail");
				response.put("message", "User not found");
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

	public ResponseEntity<?> resetPasswordLoggedIn(ResetPasswordRequest passwordReq, HttpServletResponse responseMap) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			final LoginUser user1 = loginUser.findByUsername(auth.getName());
			if (user1 != null) {
				if (bcryptEncoder.matches(passwordReq.getCurrentPassword(), user1.getPassword())) {
					user1.setPassword(bcryptEncoder.encode(passwordReq.getPassword()));
					user1.setResetPassword(false);
					loginUser.saveAndFlush(user1);
					response.put("indicator", "success");
					response.put("message", "Password updated successfully");
					return new ResponseEntity<>(response, HttpStatus.OK);
				} else {
					response.put("indicator", "fail");
					response.put("message", "Incorrect credentials");
					return new ResponseEntity<>(response, HttpStatus.OK);
				}
			} else {
				response.put("indicator", "fail");
				response.put("message", "Error Occured, if issue persists please contact administrator");
				return new ResponseEntity<>(response, HttpStatus.OK);
			}
		} catch (BadCredentialsException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Incorrect credentials";
		} catch (Exception e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Error Occured, if issue persists please contact administrator";
		}

		if (message != null)
			response.put("message", message);

		return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
	}

	public ResponseEntity<?> authorize(JwtRequest authenticationRequest, HttpServletResponse responseMap) {
		final String token;
		String message = null;

		HashMap<String, Object> response = new HashMap<>();

		try {
			authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());
			LoginUser user = loginUser.findByUsername(authenticationRequest.getUsername());
			final UserDetails userDetails = new CustomUserDetails(user);

			if (user.isResetPassword()) {
				token = UUID.randomUUID().toString();
				response.put("indicator", "success");
				user.setRestetToken(token);
				user.setFailurecount(0);
				user.setRestetTokenCreatedDate(new Date());
				loginUser.saveAndFlush(user);
				response.put("message", "User logined successfully");
				return new ResponseEntity<>(response, HttpStatus.OK);
			} else {
				token = jwtTokenUtil.generateToken(userDetails);
				response.put("indicator", "success");
				response.put("token", token);
				response.put("role", user.getRole());
				response.put("expiry", timeseconds);
				user.setFailurecount(0);
				user.setToken(token);
				user.setTokenCreatedDate(new Date());
				loginUser.saveAndFlush(user);
				response.put("message", "User logined successfully");
				return new ResponseEntity<>(response, HttpStatus.OK);
			}
		} catch (AccountExpiredException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "User account Expired";
			e.printStackTrace();
		} catch (CredentialsExpiredException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "User credentials Expired";
		} catch (DisabledException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "User account disabled";
		} catch (LockedException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "User account disabled";
		} catch (BadCredentialsException e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Incorrect credentials";
		} catch (InternalAuthenticationServiceException e) {
			log.error("", e);
			response.put("indicator", "fail");
			response.put("message", "Incorrect credentials");
			log.error("User Not found: " + authenticationRequest.getUsername());
		} catch (Exception e) {
			log.error("", e);
			response.put("indicator", "fail");
			message = "Error Occured, if issue persists please contact administrator";
		}

		if (message != null)
			response.put("message", message);

		Cookie cookie = new Cookie("token", null);
		cookie.setMaxAge(0);
		cookie.setSecure(false);
		cookie.setHttpOnly(true);
		cookie.setPath("/");
		responseMap.addCookie(cookie);

		return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
	}

	private Authentication authenticate(String username, String password) throws Exception {
		return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

	}

	@Async("asyncExecutor")
	public void createUser(String username, String password, String role, boolean resetPassword, long schoolId) {
		LoginUser newUser = new LoginUser();
		newUser.setUsername(username);
		newUser.setPassword(bcryptEncoder.encode(password));
		newUser.setAccountNonExpired(true);
		newUser.setAccountNonLocked(true);
		newUser.setFailurecount(0);
		newUser.setEnabled(true);
		newUser.setCredentialsNonExpired(true);
		newUser.setCreatedDate(new Date());
		newUser.setModifiedDate(new Date());
		newUser.setFailurecount(0);
		newUser.setResetPassword(resetPassword);
		newUser.setRole(role);
		loginUser.saveAndFlush(newUser);
	}

	public ResponseEntity<?> logout() {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			LoginUser user1 = loginUser.findByUsername(auth.getName());
			user1.setToken("1234567890qwertyuiopasdfghjklzxcvbnm");
			loginUser.saveAndFlush(user1);
			response.put("indicator", "success");
			response.put("message", "Logout successfully");
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

	public ResponseEntity<?> getUsers() {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			List<LoginUser> users = loginUser.findAll();
			List<Object> list = new ArrayList<Object>();
			for (int i = 0; i < users.size(); i++) {
				HashMap<String, Object> loginusr = new HashMap<>();
				loginusr.put("username", users.get(i).getUsername());
				loginusr.put("accountNonLocked", users.get(i).isAccountNonLocked());
				loginusr.put("enabled", users.get(i).isEnabled());
				list.add(loginusr);
			}

			response.put("indicator", "success");
			response.put("users", list);
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

	public ResponseEntity<?> saveUserAccountChanges(UserSettingRequest user) {

		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			LoginUser user1 = loginUser.findByUsername(auth.getName());
			String role = user1.getRole();
			if (role.equals("SUPERUSER") || role.equals("ADMIN")) {
				LoginUser tuser = loginUser.findByUsername(user.getUsername());
				if (tuser != null) {
					tuser.setAccountNonLocked(user.isAccountNonLocked());
					tuser.setEnabled(user.isEnabled());
					loginUser.saveAndFlush(tuser);
					response.put("users", user);
					response.put("indicator", "success");
				} else {
					response.put("indicator", "fail");
					response.put("message", "Username not found");
				}
				return new ResponseEntity<>(response, HttpStatus.OK);
			} else {
				response.put("status", 401);
				response.put("message", "Unauthorized");
				return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
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

	public ResponseEntity<?> resetUserPassword(ResetPasswordRequest resetPasss) {

		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			LoginUser user1 = loginUser.findByUsername(auth.getName());
			String role = user1.getRole();
			if (role.equals("SUPERUSER") || role.equals("ADMIN")) {
				LoginUser tuser = loginUser.findByUsername(resetPasss.getUsername());
				if (tuser != null) {

					tuser.setResetPassword(true);
					tuser.setPassword(bcryptEncoder.encode(resetPasss.getPassword()));
					loginUser.saveAndFlush(tuser);
					response.put("indicator", "success");
					response.put("message", "Temporary Password updated successfully");

				} else {
					response.put("indicator", "fail");
					response.put("message", "Username not found");
				}
				return new ResponseEntity<>(response, HttpStatus.OK);
			} else {
				response.put("status", 401);
				response.put("message", "Unauthorized");
				return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
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

	public ResponseEntity<?> checkUsername(String username) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			LoginUser users = loginUser.findByUsername(username);
			if (users == null)
				response.put("check", true);
			else
				response.put("check", false);
			response.put("indicator", "success");
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

	public ResponseEntity<?> getUser(String username) {
		HashMap<String, Object> response = new HashMap<>();
		String message = null;
		try {
			LoginUser user = loginUser.findByUsername(username);
			response.put("indicator", "success");
			response.put("user", user);
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

}
