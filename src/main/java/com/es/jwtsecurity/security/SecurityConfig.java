package com.es.jwtsecurity.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private RsaKeyProperties rsaKeys;

    /**
     * BEAN QUE ESTABLECE EL SECURITY FILTER CHAIN
     * Mét odo que establece una serie de filtros de seguridad para nuestra API
     * ¿Para qué sirve este mét odo?
     * Este mét odo sirve para establecer los filtros de seguridad que las peticiones deberán cumplir antes de
     * llegar al endpoint al que se dirijan
     * <p>
     * request ------> filtro1 -> filtro2 -> filtro3 ... -> endpoint
     * <p>
     * Por así decirlo, al cargar la aplicación, Spring Security coge lo que tengamos aquí definido y lo "pone"
     * delante de nuestra app a modo de filtros de seguridad. Esto lo hace automáticamente.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(csrf -> csrf.disable()) // Deshabilitamos "Cross-Site Request Forgery" (CSRF) (No lo trataremos en este ciclo)
                .authorizeHttpRequests(auth -> auth // Filtros para securizar diferentes endpoints de la aplicación
                        .requestMatchers("/usuarios/login", "/usuarios/register").permitAll() // Filtro que deja pasar todas las peticiones que vayan a los endpoints que definamos
                        .requestMatchers("/ruta_protegida/**").authenticated()
                        .anyRequest().authenticated() // Para el resto de peticiones, el usuario debe estar autenticado
                )
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults())) // Establecemos el que el control de autenticacion se configure con jwt
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults())
                .build();

    }


    /**
     * Mét odo que carga en el Spring ApplicationContext un Bean de tipo PasswordEncoder
     * ¿Por qué este mét odo? ¿Para qué sirve este mét odo?
     * Este mét odo está aquí para que podamos inyectar donde nos plazca objetos de tipo PasswordEncoder
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    /**
     * Mét odo que carga en el Spring ApplicationContext un Bean de tipo AuthenticationManager
     * ¿Por qué este mét odo? ¿Para qué sirve este mét odo?
     * Este mét odo está aquí para que podamos inyectar donde nos plazca objetos de tipo AuthenticationManager
     * @param authenticationConfiguration
     * @return
     * @throws Exception
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Decodifica un token
     * @return
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey()).privateKey(rsaKeys.privateKey()).build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));

        return new NimbusJwtEncoder(jwks);
    }
}