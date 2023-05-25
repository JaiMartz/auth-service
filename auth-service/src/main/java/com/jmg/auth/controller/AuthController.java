package com.jmg.auth.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.jmg.auth.dto.TokenDto;
import com.jmg.auth.dto.UserDto;
import com.jmg.auth.service.AuthService;

@RestController
@RequestMapping("/auth")
public class AuthController {

	@Autowired
	private AuthService service;

	@PostMapping("/login")
	public ResponseEntity<TokenDto> login(@RequestBody UserDto dto) {
		TokenDto token = service.login(dto);
		return ResponseEntity.ok(token);
	}

	@PostMapping("/validate")
	public ResponseEntity<TokenDto> validate(@RequestParam String token) {
		TokenDto tokenDto = service.validate(token);
		return ResponseEntity.ok(tokenDto);
	}

	@PostMapping("/create")
	public ResponseEntity<UserDto> create(@RequestBody UserDto dto) {
		UserDto userEntity = service.saveUser(dto);
		return ResponseEntity.ok(userEntity);
	}
}
