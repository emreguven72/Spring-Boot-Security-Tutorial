package com.spring.security.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.spring.security.config.JwtService;
import com.spring.security.user.Role;
import com.spring.security.user.User;
import com.spring.security.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
	public AuthenticationResponse register(RegisterRequest registerRequest) {
		User user = new User();
		user.setFirstName(registerRequest.getFirstName());
		user.setLastName(registerRequest.getLastName());
		user.setEmail(registerRequest.getEmail());
		user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		user.setRole(Role.USER);
		
		this.userRepository.save(user);
		
		String jwtToken = jwtService.generateToken(user);
		
		return AuthenticationResponse.builder() //It's like A = new A() then set the attributes
				.token(jwtToken)
				.build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
		this.authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						authenticationRequest.getEmail(),
						authenticationRequest.getPassword()
				)
		);
		
		User user = this.userRepository.findByEmail(authenticationRequest.getEmail()).orElseThrow();
		
		String jwtToken = jwtService.generateToken(user);
		
		return AuthenticationResponse.builder() //It's like A = new A() then set the attributes
				.token(jwtToken)
				.build();
	}
	
}
