package com.javasree.ms.gatewayengine.security;

import io.jsonwebtoken.Jwts;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

public class AutherizationFilter extends BasicAuthenticationFilter {

    Environment environment;

    public AutherizationFilter(AuthenticationManager authManager, Environment environment){
        super(authManager);
        this.environment = environment;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException{
        String authorizationHeader = request.getHeader(environment.getProperty("authorization.token.header.name"));

        if(authorizationHeader == null || !authorizationHeader.startsWith(environment.getProperty("authorization.token.header.prefix"))){
            chain.doFilter(request,response);
            return;
        }

        UsernamePasswordAuthenticationToken authenticationToken = getAuthentication(request);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request){
        String authorizationHeader = request.getHeader(environment.getProperty("authorization.token.header.name"));

        if(authorizationHeader==null){
            return null;
        }

        String token = authorizationHeader.replace(environment.getProperty("authorization.token.header.prefix"),"");
        String userId = Jwts.parser()
                .setSigningKey(environment.getProperty("jwt.token.secret"))
                .parseClaimsJws(token)
                .getBody()
                .getSubject();

        List<GrantedAuthority> roles = Jwts.parser()
                .setSigningKey(environment.getProperty("jwt.token.secret"))
                .parseClaimsJws(token)
                .getBody()
                .get("roles", List.class);


        if(userId == null)
        {
            return null;
        }

        return new UsernamePasswordAuthenticationToken(userId,null,roles);
    }
}
