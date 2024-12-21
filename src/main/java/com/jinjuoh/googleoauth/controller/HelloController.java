package com.jinjuoh.googleoauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/")
    public String index() {
        return "Welcome to Jinju's Google OAuth2!";
    }

    @GetMapping("/hello")
    public String hello() {
        return "Hello, Jinju!";
    }
}
