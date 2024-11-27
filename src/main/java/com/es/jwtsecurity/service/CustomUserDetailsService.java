package com.es.jwtsecurity.service;

import com.es.jwtsecurity.dto.UsuarioRegisterDTO;
import com.es.jwtsecurity.model.Usuario;
import com.es.jwtsecurity.repository.UsuarioRepository;
import com.es.jwtsecurity.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    /**
     * usuarioRepository es un objeto de tipo {@link UsuarioRepository}
     * La instanciación del objeto usuarioRepository viene inyectada automáticamente por Spring Boot
     */
    @Autowired
    private UsuarioRepository usuarioRepository;
    /**
     * passwordEncoder es un objeto de tipo {@link PasswordEncoder}
     * ¿De dónde sale la inicialización de este objeto?
     * La inicialización de este objeto viene dada en la clase {@link SecurityConfig},
     * más concretamente en el mét odo {@link SecurityConfig#passwordEncoder()}
     */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * ¡IMPORTANTE!
     * SpringSecurity necesita que implementemos la interfaz {@link UserDetailsService}.
     * La interfaz UsersDetailsService contiene un único mét odo {@link UserDetailsService#loadUserByUsername(String)}
     * El mét odo loadUserByUsername busca en la base de datos al usuario por su userName.
     * Con este mét odo, SpringSecurity tendría toda la configuración necesaria para poder gestionar nuestros Usuarios
     * @param username the username identifying the user whose data is required.
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // BUSCO EL USUARIO POR SU NOMBRE EN LA BDD
        Usuario usuario = usuarioRepository
                .findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario No encontrado"));

        /* RETORNAMOS UN USERDETAILS
        El mét odo loadUserByUsername nos fuerza a devolver un objeto de tipo UserDetails.
        Tenemos que convertir nuestro objeto de tipo Usuario a un objeto de tipo UserDetails
        ¡No os preocupéis, esto es siempre igual!
         */
        // User pertenece a SpringSecurity

        return User // User pertenece a SpringSecurity
                .builder()
                .username(usuario.getUsername())
                .password(usuario.getPassword())
                .roles(usuario.getRoles().split(","))
                .build();
    }

    /**
     * Mét odo para registrar un nuevo Usuario en la BDD
     * @param usuarioRegisterDTO
     * @return
     */
    public UsuarioRegisterDTO registerUser(UsuarioRegisterDTO usuarioRegisterDTO) {
        // Comprobamos que el usuario no existe en la base de datos
        if (usuarioRepository.findByUsername(usuarioRegisterDTO.getUsername()).isPresent()) {
            throw new IllegalArgumentException("El nombre de usuario ya existe");
        }

        // Creamos la instancia de
        Usuario newUsuario = new Usuario();

        /*
         La password del newUsuario debe estar hasheada, así que usamos el passwordEncoder que tenemos definido.
         ¿De dónde viene ese passwordEncoder?
         El objeto passwordEncoder está definido al principio de esta clase.
         */
        newUsuario.setPassword(passwordEncoder.encode(usuarioRegisterDTO.getPassword())); // Hashear la contraseña
        newUsuario.setUsername(usuarioRegisterDTO.getUsername());
        newUsuario.setRoles(usuarioRegisterDTO.getRoles());

        // Guardamos el newUsuario en la base de datos... igual que siempre
        usuarioRepository.save(newUsuario);

        return usuarioRegisterDTO;
    }
}