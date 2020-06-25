package com.open.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.open.userservice.entity.UserDetails;

@Repository
public interface UserDetailsRepository extends JpaRepository<UserDetails, String> {

	@Query(value = "SELECT user FROM UserDetails user WHERE user.username=:username ")
	UserDetails findByUsername(@Param("username") String username);

}
