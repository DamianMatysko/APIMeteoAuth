package com.meteoauth.MeteoAuth.controller;

import com.meteoauth.MeteoAuth.assembler.UserAssembler;
import com.meteoauth.MeteoAuth.config.CurrentUser;
import com.meteoauth.MeteoAuth.dto.*;
import com.meteoauth.MeteoAuth.entities.Station;
import com.meteoauth.MeteoAuth.entities.User;
import com.meteoauth.MeteoAuth.oAuth2.GeneralUtils;
import com.meteoauth.MeteoAuth.oAuth2.LocalUser;
import com.meteoauth.MeteoAuth.repository.RoleRepository;
import com.meteoauth.MeteoAuth.repository.StationsRepository;
import com.meteoauth.MeteoAuth.repository.UserRepository;
import com.meteoauth.MeteoAuth.services.MyUserDetailsService;
import com.meteoauth.MeteoAuth.services.TokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.annotation.security.PermitAll;
import javax.validation.Valid;
import java.util.Optional;
import java.util.Set;

@PermitAll
@RestController
@RequestMapping({"/api/authentication"})
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final TokenProvider tokenProvider;
    private final MyUserDetailsService userDetailsService;
    private final UserAssembler userAssembler;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final StationsRepository stationsRepository;

    public AuthenticationController(AuthenticationManager authenticationManager, TokenProvider tokenProvider, MyUserDetailsService userDetailsService, UserAssembler userAssembler, UserRepository userRepository, RoleRepository roleRepository, StationsRepository stationsRepository) {
        this.authenticationManager = authenticationManager;
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
        this.userAssembler = userAssembler;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.stationsRepository = stationsRepository;
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            System.out.println(authenticationRequest.getUsername());
            System.out.println(authenticationRequest.getPassword());
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new Exception("Incorrect username or password", e);
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = tokenProvider.generateToken(userDetails);
        final String refreshToken = tokenProvider.generateRefreshToken(userDetails);

        return ResponseEntity.ok(new UserAuthenticationResponse(jwt, refreshToken));
    }


    @RequestMapping(value = "/refreshToken", method = RequestMethod.POST)
    public ResponseEntity<?> refreshToken(@RequestBody @Valid RefreshTokenRequest refreshTokenRequest) throws Exception {
        try {
            final String authorizationHeader = refreshTokenRequest.getJwt();
            String subject = null;
            String refreshToken = null;

//            if(authorizationHeader == null){
//                return ResponseEntity.badRequest().build();
//            }

            if (authorizationHeader.startsWith("Bearer ")) {
                refreshToken = authorizationHeader.substring(7);
            } else {
                refreshToken = authorizationHeader;
            }
            if (!tokenProvider.validateToken(refreshToken)) {
                return ResponseEntity.badRequest().build();
            }

            subject = tokenProvider.extractSubject(refreshToken);
            UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
            final String token = tokenProvider.generateToken(userDetails);

            return ResponseEntity.ok(new UserAuthenticationResponse(token, refreshToken));
        } catch (BadCredentialsException e) {
            throw new Exception("Refresh token missing", e);
        }
    }

    @RequestMapping(value = "/authenticate-station/{id}", method = RequestMethod.GET)
    public ResponseEntity<?> createAuthenticationTokenForStation(@PathVariable Long id) throws Exception {
        Optional<Station> station = stationsRepository.findById(id);
        if (station.isEmpty()) {
            throw new Exception("Station not found");
        }
        final String jwt;
        jwt = tokenProvider.generateTokenForStation(station.get());
        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }

    @PostMapping("/register")
    public UserDtoResponse addUser(@RequestBody @Valid UserDtoRequest userDtoRequest) {
        User user = userAssembler.getUser(userDtoRequest);
        user.setRoles(Set.of(roleRepository.findByName("USER_ROLE")));
        user.setEnabled(true);
        user.setProvider("Local");
        user = userRepository.save(user);
        return userAssembler.getUserDtoResponse(user);
    }

    @GetMapping("/user/me")
    public ResponseEntity<?> getCurrentUser(@CurrentUser LocalUser user) {
        return ResponseEntity.ok(GeneralUtils.buildUserInfo(user));
    }
}