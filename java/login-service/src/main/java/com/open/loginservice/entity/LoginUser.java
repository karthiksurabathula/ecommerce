package com.open.loginservice.entity;

import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicUpdate;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.sun.istack.NotNull;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "login")
@DynamicUpdate
@JsonInclude(Include.NON_NULL)
public class LoginUser {

	@JsonIgnore
	@Id
	@NotNull
	private String username;
	@NotNull
	@JsonIgnore
	private String password;
	@NotNull
	@JsonIgnore
	private boolean accountNonExpired;
	@NotNull
	@JsonIgnore
	private boolean accountNonLocked;
	@NotNull
	@JsonIgnore
	private boolean credentialsNonExpired;
	@JsonIgnore
	@NotNull
	private boolean enabled;
	@JsonIgnore
	@NotNull
	private Date createdDate;
	@JsonIgnore
	@NotNull
	private Date modifiedDate;
	@JsonIgnore
	@Lob
	private String token;
	@JsonIgnore
	private Date tokenCreatedDate;
	private String role;

	@NotNull
	private boolean resetPassword;
	private String restetToken;
	private Date restetTokenCreatedDate;
		
	@Column(nullable=false)
	private int failurecount;
	@Column(nullable=true)
	private Date lastLoginFailureTime;
	@Column(nullable=true)
	private String lastLoginFailureIpAddress;

}
