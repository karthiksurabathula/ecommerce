package com.open.loginservice.model.userdetails;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserDetailsResponse {

	private String indicator;
	private String message;
	private UserDetails userDetails;
}
