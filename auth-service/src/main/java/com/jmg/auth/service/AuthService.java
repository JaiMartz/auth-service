package com.jmg.auth.service;

import java.util.Optional;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.jmg.auth.config.JwtProvider;
import com.jmg.auth.dto.TokenDto;
import com.jmg.auth.dto.UserDto;
import com.jmg.auth.entity.UserEntity;
import com.jmg.auth.repository.UserRepository;

@Service
public class AuthService {

	@Autowired
	private UserRepository repository;

	@Autowired
	private PasswordEncoder encoder;

	@Autowired
	private JwtProvider provider;

	@Autowired
	private ModelMapper mapper;

	public UserDto saveUser(UserDto dto) {
		Optional<UserEntity> user = repository.findByUsername(dto.getUsername());
		if (user.isPresent()) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, String.format("El usuario % ya existe", dto.getUsername()));
		}
		UserEntity entity = repository.save(new UserEntity(dto.getUsername(), encoder.encode(dto.getPassword())));
		return mapper.map(entity, UserDto.class);
	}
	
	public TokenDto validate(String token) {
		if (!provider.validate(token)) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
		}
		String username = provider.getUsernameFromToken(token);
		Optional<UserEntity> entity = repository.findByUsername(username);
		if (!entity.isPresent()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
		}
		return new TokenDto(token);
	}
	
	public TokenDto login(UserDto user) {
		Optional<UserEntity> result = repository.findByUsername(user.getUsername());
		if (!result.isPresent()) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
		}
		if (encoder.matches(user.getPassword(), result.get().getPassword())) {
			return new TokenDto(provider.createToken(result.get()));
		}
		throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
	}
}
