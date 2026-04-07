package com.shopleft.spring_security.config;

import java.util.List;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import com.shopleft.spring_security.config.jwt.AuthEntryPoint;
import com.shopleft.spring_security.config.jwt.AuthTokenFilter;
import com.shopleft.spring_security.repository.UserRepository;
import com.shopleft.spring_security.service.CustomOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager, AuthTokenFilter authTokenFilter) throws Exception {
    http
        .securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())
        .authenticationManager(authenticationManager)
        .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(authEntryPoint))
        .sessionManagement(sessionManagement ->
            sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/v1/passport/auth", "/api/v1/signup").permitAll()
            .anyRequest().authenticated()
        );

    http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
    return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http, CustomOidcUserService customOidcUserService) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/admin/**").hasRole("ADMIN")
            .requestMatchers("/user").hasAnyRole("USER", "ADMIN", "DEVELOPERS")
            .requestMatchers("/me").authenticated()
            .anyRequest().permitAll()
        )
        // Keep form login for local account testing.
        .formLogin(form -> form.loginPage("/login").permitAll())
        // Enable Google login and persist/update OAuth users in DB.
        .oauth2Login(oauth2 -> oauth2
            .loginPage("/login")
            .userInfoEndpoint(userInfo -> userInfo
                .oidcUserService(customOidcUserService)
            )
            .defaultSuccessUrl("/user", true)
        )
        .logout(LogoutConfigurer::permitAll);

    return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean("dbUserDetailsService")
    public UserDetailsService dbUserDetailsService(UserRepository userRepository) {
        return username -> {
            com.shopleft.spring_security.models.User appUser = userRepository.findByUsername(username);

            if (appUser == null) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            List<SimpleGrantedAuthority> authorities = appUser.getAuthorities().stream()
                    .map(authority -> toRoleAuthority(authority.getAuthority()))
                    .toList();

            return new User(appUser.getUsername(), appUser.getPassword(), authorities);
        };
    }

    @Bean("ldapAwareUserDetailsService")
    public UserDetailsService ldapAwareUserDetailsService(UserRepository userRepository, LdapTemplate ldapTemplate) {
        return username -> {
            com.shopleft.spring_security.models.User appUser = userRepository.findByUsername(username);

            if (appUser != null) {
                List<SimpleGrantedAuthority> authorities = appUser.getAuthorities().stream()
                        .map(authority -> toRoleAuthority(authority.getAuthority()))
                        .toList();

                return new User(appUser.getUsername(), appUser.getPassword(), authorities);
            }

            String userDn = "uid=" + username + ",ou=people,dc=springframework,dc=org";
            List<String> ldapUsers = ldapTemplate.search(
                    LdapQueryBuilder.query().base("ou=people").where("uid").is(username),
                    (AttributesMapper<String>) attributes -> (String) attributes.get("uid").get()
            );

            if (ldapUsers.isEmpty()) {
                throw new UsernameNotFoundException("User not found: " + username);
            }

            Set<SimpleGrantedAuthority> ldapAuthorities = new LinkedHashSet<>(ldapTemplate.search(
                    LdapQueryBuilder.query().base("ou=groups").where("uniqueMember").is(userDn),
                    (AttributesMapper<SimpleGrantedAuthority>) attributes ->
                            toRoleAuthority((String) attributes.get("cn").get())
            ));

            if (ldapAuthorities.isEmpty()) {
                ldapAuthorities.add(toRoleAuthority("USER"));
            }

            return new User(username, "N/A", ldapAuthorities);
        };
    }

    private SimpleGrantedAuthority toRoleAuthority(String authority) {
        if (authority == null || authority.isBlank()) {
            return new SimpleGrantedAuthority("ROLE_USER");
        }

        String normalized = authority.startsWith("ROLE_") ? authority : "ROLE_" + authority.toUpperCase();
        return new SimpleGrantedAuthority(normalized);
    }

    @Bean
    public AuthenticationProvider daoAuthenticationProvider(@Qualifier("dbUserDetailsService") UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
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
        return new ProviderManager(List.of(ldapAuthenticationProvider, daoAuthenticationProvider));
    }
}