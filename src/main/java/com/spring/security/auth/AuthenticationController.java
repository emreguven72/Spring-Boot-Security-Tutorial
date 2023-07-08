package com.spring.security.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	private final AuthenticationService authenticationService;
	
	@PostMapping("/register")
	public ResponseEntity<AuthenticationResponse> register(
		@RequestBody RegisterRequest registerRequest
	) {
		return ResponseEntity.ok(this.authenticationService.register(registerRequest));
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<AuthenticationResponse> register(
		@RequestBody AuthenticationRequest authenticationRequest
	) {
		return ResponseEntity.ok(this.authenticationService.authenticate(authenticationRequest));
	}
	
	@GetMapping()
	public String sayHello() {
		return "Hello from public place";
	}
	
}
