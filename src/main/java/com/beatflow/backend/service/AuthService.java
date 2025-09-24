import com.beatflow.backend.dto.AuthResponse;
import com.beatflow.backend.dto.LoginRequest;
import com.beatflow.backend.dto.SignUpRequest;
import com.beatflow.backend.model.User;
import com.beatflow.backend.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    /**
     * Registers a new user.
     * @param request The signup request containing user details.
     * @return The saved User object.
     */
    public User signup(SignUpRequest request) {
        // Check if a user with the given email already exists
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new IllegalArgumentException("Email already in use.");
        }
        
        // Create a new user and hash the password before saving
        User user = new User();
        user.setName(request.name());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        
        return userRepository.save(user);
    }

    /**
     * Authenticates an existing user and returns a JWT.
     * @param request The login request containing user credentials.
     * @return An AuthResponse containing the JWT.
     */
    public AuthResponse login(LoginRequest request) {
        // This tells Spring Security to find the user and securely compare the passwords.
        // If the password or email is wrong, it will throw an exception.
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.email(),
                request.password()
            )
        );
        
        // If authentication was successful, generate and return the token.
        var user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new IllegalArgumentException("Invalid email or password."));
        var jwtToken = jwtService.generateToken(user);
        
        return new AuthResponse(jwtToken);
    }
}
