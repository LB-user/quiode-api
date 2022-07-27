package com.quiode.payload.controllers;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.Null;

import com.mongodb.lang.Nullable;
import com.quiode.models.Role;
import com.quiode.models.User;
import com.quiode.payload.request.ForgotPasswordRequest;
import com.quiode.payload.request.LoginRequest;
import com.quiode.payload.request.ResetPasswordRequest;
import com.quiode.payload.request.SignupRequest;
import com.quiode.payload.response.JwtResponse;
import com.quiode.payload.response.MessageResponse;
import com.quiode.repositories.RoleRepository;
import com.quiode.repositories.UserRepository;
import com.quiode.security.jwt.JwtUtils;
import com.quiode.security.services.EmailService;
import com.quiode.security.services.RandomPassword;
import com.quiode.security.services.UserDetailsImpl;
import com.quiode.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.repository.query.Param;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.quiode.models.ERole;

import static ch.qos.logback.core.joran.action.ActionConst.NULL;
import static com.quiode.security.services.RandomCode.generateRandomPassword;

// @CrossOrigin(origins = "*", maxAge = 3600)
// @CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials="true")

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials="true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    EmailService emailService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) throws MessagingException {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }
        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();
        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        String randomCode = generateRandomPassword(6);
        user.setResetToken("");
        // user.setVerificationCode(encoder.encode("123456"));
        user.setVerificationCode(encoder.encode(randomCode));
        userRepository.save(user);
        emailService.sendRegisterMail(user, randomCode);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest)  throws MessagingException {
        if (userRepository.existsByUsername(forgotPasswordRequest.getUsername())) {
            User user = userRepository.findByUsername(forgotPasswordRequest.getUsername());
            String token = RandomPassword.getPassword(30);

            user.setResetToken(token);
            emailService.sendForgotPasswordMail(user, token);

            return ResponseEntity.ok(new MessageResponse("Un email vous à été envoyé!"));
        }
        if (userRepository.existsByEmail(forgotPasswordRequest.getUsername())) {
            User user = userRepository.findByEmail(forgotPasswordRequest.getUsername());
            String token = RandomPassword.getPassword(30);

            user.setResetToken(token);
            emailService.sendForgotPasswordMail(user, token);

            return ResponseEntity.ok(new MessageResponse("Un email vous à été envoyé!"));

        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Error: Cet utilisateur n'existe pas!"));
    }
    @PostMapping("/reset-password")
    public ResponseEntity<?> showResetPasswordForm(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        User user = userRepository.findByResetToken(resetPasswordRequest.getResetToken());
        String newPassword = resetPasswordRequest.getPassword();
        String newConfirmPassword = resetPasswordRequest.getConfirmPassword();
        if (newPassword.equals(newConfirmPassword)) {
            user.setPassword(encoder.encode(resetPasswordRequest.getPassword()));
            user.setResetToken("");

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), resetPasswordRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
        }
        return ResponseEntity
                .badRequest()
                .body(new MessageResponse("Error: le mot de passe et la confirmation doivent être identique!"));
    }
}