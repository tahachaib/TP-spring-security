package com.example.springsecurity.filter;

import com.example.springsecurity.utils.JwtUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        // a. Est-ce que le header contient une Authorization
        final String authorizationHeader = httpServletRequest.getHeader("Authorization");

        // b. Si authorizationHeader est null, vide, ou ne commence pas Bearer
        if (authorizationHeader == null || authorizationHeader.isEmpty() ||
                !authorizationHeader.startsWith("Bearer")) {
            // if Authorization header does not exist or does not start with Bearer, then skip this filter
            // and continue to execute the next filter class
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        // c. Récupérer le token et vérifier sa validité
        final String token = authorizationHeader.split(" ")[1].trim();
        if (!jwtUtil.validate(token)) {
            // if token is not valid, then skip this filter
            // and continue to execute the next filter class.
            // This means authentication is not successful since the token is invalid.
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        // d. Si la requête a passé les trois vérifications, donc on récupère les informations de l’utilisateur à travers son username.
        String username = jwtUtil.getUsername(token);

        // e. Finalement on va créer un objet de type UsernamePasswordAuthenticationToken
        // avec un constructeur différent de celui utilisé dans la question 14 (partie 3).
        UsernamePasswordAuthenticationToken upassToken = new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
        upassToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

        // finally, give the authentication token to Spring Security Context
        SecurityContextHolder.getContext().setAuthentication(upassToken);

        // end of the method, so go for the next filter class
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
