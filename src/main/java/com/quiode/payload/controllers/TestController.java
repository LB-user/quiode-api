package com.quiode.payload.controllers;

import com.quiode.models.User;
import com.quiode.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// @CrossOrigin(origins = "*", maxAge = 3600)
//@CrossOrigin(origins = "http://localhost:8081", maxAge = 3600, allowCredentials="true")
@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600, allowCredentials="true")
@RestController
@RequestMapping("/api/test")

public class TestController {

    private final UserRepository userRepository;

    @Autowired
    public TestController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/getall")
    @ResponseBody
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }
    @GetMapping("/all")
    @ResponseBody
    public String allAccess() {
        return "{\"text\": \"Public Content.\"}"; }
    @GetMapping("/user")
    @ResponseBody
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "{\"text\": \"User Content.\"}";
    }
    @GetMapping("/mod")
    @ResponseBody
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    public String moderatorAccess() { return "{\"text\": \"Moderator Content.\"}"; }
    @GetMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "{\"text\": \"Admin Content.\"}";
    }
}