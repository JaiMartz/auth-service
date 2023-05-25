package com.jmg.auth.config;

import java.util.Base64;
import java.util.Date;
import java.util.Map;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.jmg.auth.entity.UserEntity;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtProvider {

	@Value("${jwt.secret}")
	private String secret;

	@PostConstruct
	public void init() {
		secret = Base64.getEncoder().encodeToString(secret.getBytes());
	}

	public String createToken(UserEntity user) {
		Map<String, Object> claims = Jwts.claims().setSubject(user.getUsername());
		claims.put("id", user.getId());
		//TODO: Quitar company-name
		claims.put("company-name", "lm2a");
		Date now = new Date();
		Date expiration = new Date(now.getTime() + 3600 * 1000);

		return Jwts.builder()
				.setClaims(claims)
				.setIssuedAt(now)
				.setExpiration(expiration)
				.signWith(SignatureAlgorithm.HS256, secret)
				.compact();
	}
	
	public boolean validate(String token) {
		try {
			Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
			return true;
		} catch (ExpiredJwtException e) {
			return false;
		}
	}
	
	public String getUsernameFromToken(String token) {
		try {
			return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().getSubject();
		} catch (ExpiredJwtException e) {
			throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token invalido.");
		}
	}
}
