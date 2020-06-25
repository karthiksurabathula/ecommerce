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

	@Id
	@NotNull
	private String username;
	@NotNull
	@JsonIgnore
	private String password;
	@NotNull
	private boolean accountNonExpired;
	@NotNull
	private boolean accountNonLocked;
	@NotNull
	private boolean credentialsNonExpired;
	@NotNull
	private boolean enabled;
	@NotNull
	private Date createdDate;
	@NotNull
	private Date modifiedDate;
	@Lob
	private String token;
	private Date tokenCreatedDate;
	private String role;

	@JsonIgnore
	@NotNull
	private boolean resetPassword;
	@JsonIgnore
	private String restetToken;
	@JsonIgnore
	private Date restetTokenCreatedDate;
	@JsonIgnore	
	@Column(nullable=false)
	private int failurecount;
	@JsonIgnore
	@Column(nullable=true)
	private Date lastLoginFailureTime;
	@JsonIgnore
	@Column(nullable=true)
	private String lastLoginFailureIpAddress;

}
