package br.com.alura.forum.security;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TokenService {


    @Value("${forum.jwt.expiration}")
    private long expirationInMillis;
    @Value("${forum.jwt.secret}")
    private String secret;

    public String gerarToken(Authentication authenticate) {
        Usuario principal = (Usuario) authenticate.getPrincipal();

        Date agora = new Date();
        Date exp = new Date(agora.getTime() + expirationInMillis);
        return Jwts.builder()
                .setIssuer("API do Forum da Alura")
                .setSubject(principal.getId().toString())
                .setIssuedAt(agora)
                .setExpiration(exp)
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();
    }
}
