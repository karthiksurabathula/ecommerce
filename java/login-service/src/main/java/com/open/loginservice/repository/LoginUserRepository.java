package com.open.loginservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.open.loginservice.entity.LoginUser;

@Repository
public interface LoginUserRepository extends JpaRepository<LoginUser, String> {

	@Query(value = "SELECT user FROM LoginUser user WHERE user.username=:username ")
	LoginUser findByUsername(@Param("username") String username);
	
	@Query(value = "SELECT user FROM LoginUser user WHERE user.restetToken=:restetToken ")
	LoginUser findByToken(@Param("restetToken") String restetToken);
	
	@Query(value = "SELECT user FROM LoginUser user WHERE user.username=:username ")
	LoginUser findFailureCount(@Param("username") String username);

}
