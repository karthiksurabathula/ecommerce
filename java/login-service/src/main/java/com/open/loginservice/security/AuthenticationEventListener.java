package com.open.loginservice.security;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.open.loginservice.entity.LoginUser;
import com.open.loginservice.repository.LoginUserRepository;

@Component
@EnableAsync(proxyTargetClass = true)
public class AuthenticationEventListener implements AsyncConfigurer {

	@Autowired
	private LoginUserRepository loginUser;
	private static final Logger log = LogManager.getLogger(AuthenticationEventListener.class);

	@EventListener
	@Async
	public void authenticationFailed(AuthenticationFailureBadCredentialsEvent event) {

		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
		String address = request.getRemoteAddr();
		String username = (String) event.getAuthentication().getPrincipal();
		try {
			LoginUser user = loginUser.findFailureCount(username);
			if (user.getFailurecount() <= 3) {
				user.setFailurecount(user.getFailurecount() + 1);
				user.setLastLoginFailureIpAddress(address);
				user.setLastLoginFailureTime(new Date());
				loginUser.saveAndFlush(user);
				log.warn("Bad Credentials: "+username);
			}
			if (user.getFailurecount() == 3) {
				user.setAccountNonLocked(false);
				loginUser.saveAndFlush(user);
				log.warn("User Locked: "+username);
			}
		} catch (Exception e) {
			log.error("",e);
		}
	}
}
