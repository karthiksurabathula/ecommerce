package com.open.userservice.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.DynamicUpdate;

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
@Table(name = "userDetails")
@DynamicUpdate
@JsonInclude(Include.NON_NULL)
public class UserDetails {
	
	@Id
	@NotNull
	private String username;
	@NotNull
	private String email;
	@Column(nullable=true)
	private String phone;
	@Column(nullable=true)
	private String address;
	@Column(nullable=true)
	private int pincode;
	
}
