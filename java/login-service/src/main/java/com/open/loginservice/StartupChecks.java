package com.open.loginservice;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.open.loginservice.entity.LoginUser;
import com.open.loginservice.repository.LoginUserRepository;
import com.open.loginservice.service.JwtService;

@Component
public class StartupChecks {

	@Autowired
	private JwtService jwsService;
	@Autowired
	private LoginUserRepository loginUser;

	@EventListener(ApplicationReadyEvent.class)
	private void createSuperAdmin() {
		LoginUser loggedInUser = loginUser.findByUsername("su");
		if (loggedInUser == null) {
			jwsService.createUser("su", "1234", "SUPERUSER", false, 0);
		}
	}
}
