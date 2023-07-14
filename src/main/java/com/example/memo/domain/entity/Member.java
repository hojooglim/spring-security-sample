package com.example.memo.domain.entity;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "member")
@Getter
@NoArgsConstructor
public class Member {
	@Id
	private String email;
	@Setter
	private String name;
	private String password;
	@ElementCollection
	private Set<String> roles;
	private LocalDateTime createdAt;

	public Member(String email, String name, String password, Set<String> roles, LocalDateTime createdAt) {
		this.email = email;
		this.name = name;
		this.password = password;
		this.roles = roles;
		this.createdAt = createdAt;
	}

	private Long kakaoId;
	public Member(String email, String name, String password, Set<String> roles, LocalDateTime createdAt, Long kakaoId) {
		this.email = email;
		this.name = name;
		this.password = password;
		this.roles = roles;
		this.createdAt = createdAt;
		this.kakaoId = kakaoId;
	}


}
