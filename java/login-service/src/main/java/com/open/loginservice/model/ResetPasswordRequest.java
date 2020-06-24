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
public class ResetPasswordRequest implements Serializable {

	private static final long serialVersionUID = 5617044520139732795L;

	private String currentPassword;
	private String password;
	private String restetToken;
	private String username;

}
