package com.example.springsecurity.securityconfig;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    @Autowired
    BCryptPasswordEncoder passwordEncoder;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> users = new HashMap<>();
        users.put("xproce", passwordEncoder.encode("12345"));
        if (users.containsKey(username))
            return new User(username, users.get(username), new ArrayList<>());
        // if this is thrown, then we won't generate JWT token.
        throw new UsernameNotFoundException(username);
    }
}
