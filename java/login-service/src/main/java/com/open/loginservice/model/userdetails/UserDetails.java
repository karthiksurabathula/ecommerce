package com.open.loginservice.model.userdetails;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserDetails {

	private String username;
	private String email;
	private String phone;
	private String address;
	private int pincode;
	
}
