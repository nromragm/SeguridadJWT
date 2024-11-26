
# Explicaciones detalladas de cada clase en Spring Security

---

## **1. `User` Entity**
La clase `User` representa la entidad del usuario en la base de datos. Es una clase básica de JPA que mapea los usuarios de la aplicación a una tabla en la base de datos.

### Código:
```java
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    private String roles; // e.g., "ROLE_USER,ROLE_ADMIN"

    // Getters y setters
}
```

### Explicación:
1. **Anotación `@Entity`**: Marca esta clase como una entidad JPA que se mapea a una tabla en la base de datos.
2. **Propiedades**:
    - `id`: Clave primaria generada automáticamente.
    - `username`: Nombre de usuario único para identificar al usuario.
    - `password`: Contraseña del usuario que estará almacenada como un hash.
    - `roles`: Cadena que contiene los roles del usuario (por ejemplo, `"ROLE_USER"` o `"ROLE_ADMIN"`).
3. **Validación**:
    - `@Column(unique = true)`: Asegura que el nombre de usuario sea único.
    - `@Column(nullable = false)`: Asegura que `username` y `password` no sean nulos.

---

## **2. `CustomUserDetailsService`**
Esta clase implementa `UserDetailsService` de Spring Security y se utiliza para cargar detalles del usuario desde la base de datos durante la autenticación. También incluye la lógica de registro de usuarios.

### Código:
```java
@Service
public class CustomUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public CustomUserDetailsService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(user.getRoles().split(",")) // Convierte roles a autoridades
                .build();
    }

    public User registerUser(User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            throw new IllegalArgumentException("El nombre de usuario ya existe");
        }

        user.setPassword(passwordEncoder.encode(user.getPassword())); // Hashear la contraseña
        user.setRoles("ROLE_USER"); // Rol predeterminado
        return userRepository.save(user);
    }
}
```

### Explicación:
1. **Método `loadUserByUsername`**:
    - Se utiliza durante el proceso de autenticación.
    - Busca un usuario por su nombre de usuario en la base de datos.
    - Convierte los datos del usuario (nombre, contraseña, roles) en un objeto `UserDetails` que Spring Security entiende.

2. **Método `registerUser`**:
    - Registra un nuevo usuario.
    - Valida que el nombre de usuario no exista previamente.
    - Hashea la contraseña usando `PasswordEncoder`.
    - Asigna el rol predeterminado `"ROLE_USER"`.
    - Guarda el usuario en la base de datos.

3. **Uso de `PasswordEncoder`**:
    - Asegura que las contraseñas se almacenen de manera segura en la base de datos.

---

## **3. `TokenService`**
Esta clase se encarga de generar tokens JWT para los usuarios autenticados.

### Código:
```java
@Service
public class TokenService {

    private final JwtEncoder encoder;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();
        String scope = authentication.getAuthorities().stream()
                .map(grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.joining(" "));

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject(authentication.getName())
                .claim("scope", scope)
                .build();

        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
```

### Explicación:
1. **JWT Claims**:
    - `issuer`: Define quién emitió el token (en este caso, "self").
    - `subject`: Es el nombre de usuario autenticado.
    - `scope`: Contiene los roles o permisos del usuario.
    - `expiresAt`: Define cuándo expira el token (por ejemplo, en 1 hora).

2. **`JwtEncoder`**:
    - Firma el token JWT con una clave privada.
    - Devuelve el token firmado como una cadena.

3. **Autenticación**:
    - Toma los detalles del usuario autenticado (`Authentication`) y los incluye en el token JWT.

---

## **4. `SecurityConfig`**
Configura la seguridad de la aplicación: protege las rutas, configura el manejo de JWT, y define cómo se autentican los usuarios.

### Código:
```java
@Configuration
public class SecurityConfig {

    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public SecurityConfig(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .authorizeRequests(auth -> auth
                        .antMatchers("/usuarios/register", "/usuarios/login").permitAll()
                        .antMatchers("/ruta_protegida").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt())
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(new RSAKey.Builder(publicKey).privateKey(privateKey).build()));
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

### Explicación:
1. **Protección de Rutas**:
    - `permitAll()`: Permite el acceso sin autenticación a `/auth/register` y `/auth/login`.
    - `authenticated()`: Requiere autenticación para `/api/protected`.

2. **Manejo de JWT**:
    - `JwtDecoder`: Verifica y valida los tokens JWT usando la clave pública.
    - `JwtEncoder`: Firma los tokens JWT usando la clave privada.

3. **Configuración de Contraseñas**:
    - `PasswordEncoder`: Usa BCrypt para encriptar contraseñas.

---

## **5. `UserController`**
Controla el registro y el inicio de sesión de usuarios.

### Código:
```java
@RestController
@RequestMapping("/usuarios")
public class UserController {

    private final CustomUserDetailsService userDetailsService;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public UserController(CustomUserDetailsService userDetailsService, AuthenticationManager authenticationManager, TokenService tokenService) {
        this.userDetailsService = userDetailsService;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody User user) {
        try {
            userDetailsService.registerUser(user);
            return ResponseEntity.status(HttpStatus.CREATED).body("Usuario registrado exitosamente");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginData.get("username"), loginData.get("password"))
            );

            String token = tokenService.generateToken(authentication);

            Map<String, String> response = new HashMap<>();
            response.put("token", token);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Nombre de usuario o contraseña inválidos");
        }
    }
}
```

### Explicación:
1. **`/register`**:
    - Llama al método `registerUser` de `CustomUserDetailsService` para registrar un nuevo usuario.
    - Maneja excepciones si el nombre de usuario ya existe.

2. **`/login`**:
    - Autentica al usuario usando `AuthenticationManager`.
    - Genera un token JWT al completar la autenticación.
    - Devuelve el token al cliente.

---

