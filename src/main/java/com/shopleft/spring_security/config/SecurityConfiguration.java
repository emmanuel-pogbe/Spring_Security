package com.shopleft.spring_security.config;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.shopleft.spring_security.config.jwt.AuthEntryPoint;
import com.shopleft.spring_security.config.jwt.AuthTokenFilter;
import com.shopleft.spring_security.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    private final AuthEntryPoint authEntryPoint;

    public SecurityConfiguration(AuthEntryPoint authEntryPoint) {
        this.authEntryPoint = authEntryPoint;
    }

	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager, AuthTokenFilter authTokenFilter) throws Exception {
		http
                .csrf(csrf->csrf.disable())
            .authenticationManager(authenticationManager)
                .exceptionHandling(exceptionHandling ->exceptionHandling.authenticationEntryPoint(authEntryPoint))
                .sessionManagement(sessionManagement->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user").hasAnyRole("USER","ADMIN","DEVELOPERS")
                    .requestMatchers("/api/v1/info").authenticated()
                    .anyRequest().permitAll()
			)
			.formLogin(Customizer.withDefaults())
			.logout(LogoutConfigurer::permitAll);
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
	}

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> {
            com.shopleft.spring_security.models.User appUser = userRepository.findByUsername(username);


            if (appUser == null) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            return new User(appUser.getUsername(), appUser.getPassword(), new ArrayList<>());
        };
    }

    @Bean
    public AuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    @Bean
    public AuthenticationProvider ldapAuthenticationProvider(BaseLdapPathContextSource contextSource) {
        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups");
        authorities.setGroupSearchFilter("(uniqueMember={0})");
        authorities.setRolePrefix("ROLE_");

        return new LdapAuthenticationProvider(authenticator, authorities);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationProvider daoAuthenticationProvider, AuthenticationProvider ldapAuthenticationProvider) {
        return new ProviderManager(List.of(daoAuthenticationProvider, ldapAuthenticationProvider));
    }
}