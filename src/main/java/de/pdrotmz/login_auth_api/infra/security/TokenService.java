package de.pdrotmz.login_auth_api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import de.pdrotmz.login_auth_api.domain.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

// Lógica do négocio

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    // Método de geração do token
    public String generateToken(User user) {
         // Trabalhando com tratamento de erro na criação do token
        try {
            // Criando algoritmo de geração do Token
            // A secret é passada pra criação do algoritmo
            Algorithm algorithm = Algorithm.HMAC256(secret);

            String token = JWT.create()
                    // Qual o nome da api ou do microservice
                    .withIssuer("login-auth-api")
                    // Quem tá recebendo o token, no caso aqui vai ser o email do usuário
                    .withSubject(user.getEmail())
                    // Tempo de expiração do curso
                    .withExpiresAt(this.generateExpirationDate())
                    // Assinatura de ciração usando o algorithm
                    .sign(algorithm);

            // Retorno do token
            return token;
        } catch(JWTCreationException exception){
            throw new RuntimeException("Erro ao autenticar !");
        }
    }

    // Função de Validação de Token
    public String validateToken(String token) {
        try {
            // Basicamente ele vai verificar tudo

            // Passando a secret key
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // O retorno vai ser a requisição do meu algorithm
            return JWT.require(algorithm)
                    // Dentro do microservice ou api em que ele esteja rodando
                    .withIssuer("login-auth-api")
                    // Junta tudo
                    .build()
                    // E verifica passando o token
                    .verify(token)
                    // e o subject vulgo o email
                    .getSubject();
        } catch(JWTVerificationException exception) {
            return null;
        }
    }

    // Função de criação do tempo do expiração
    private Instant generateExpirationDate(){
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
