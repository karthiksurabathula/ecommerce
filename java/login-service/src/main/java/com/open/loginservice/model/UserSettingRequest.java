package com.open.loginservice.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@JsonInclude(Include.NON_NULL)
public class UserSettingRequest implements Serializable  {/**
	 * 
	 */
	private static final long serialVersionUID = 5110300918894068734L;
	
	private String username;
	private boolean accountNonLocked;
	private boolean enabled;

}
