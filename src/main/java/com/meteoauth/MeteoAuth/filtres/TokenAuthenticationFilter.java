package com.meteoauth.MeteoAuth.filtres;


import com.meteoauth.MeteoAuth.entities.Station;
import com.meteoauth.MeteoAuth.repository.StationsRepository;
import com.meteoauth.MeteoAuth.services.MyUserDetailsService;
import com.meteoauth.MeteoAuth.services.StationAuthentication;
import com.meteoauth.MeteoAuth.services.TokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {
	@Autowired
	private  MyUserDetailsService myUserDetailsService;
	@Autowired
	private  StationsRepository stationsRepository;
	@Autowired
	private  TokenProvider tokenProvider;


	private  StationAuthentication stationAuthentication = new StationAuthentication();
	private static final Logger logger = LoggerFactory.getLogger(TokenAuthenticationFilter.class);



	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

		//localuser
		if (request.getRequestURI().substring(request.getContextPath().length()).equals("/api/authentication/authenticate")){
			filterChain.doFilter(request, response);
			return;
		}


		final String authorizationHeader = request.getHeader("Authorization");

		String subject = null;
		String jwt2 = null;

		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			jwt2 = authorizationHeader.substring(7);
			subject = tokenProvider.extractSubject(jwt2);
		}


		// station
		if (subject != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			if (tokenProvider.hasRole(jwt2, "ROLE_STATION")) {

				Station station = stationsRepository.getOne(Long.parseLong(subject));

				if (tokenProvider.validateTokenForStation(jwt2, station)){
					SecurityContextHolder.getContext().setAuthentication(stationAuthentication);
					filterChain.doFilter(request, response);
					return;
				}
			}

			UserDetails userDetails = this.myUserDetailsService.loadUserByUsername(subject);

			if (tokenProvider.validateToken(jwt2, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());

				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

				filterChain.doFilter(request, response);
				return;

			}

		}

// OAuth user
		try {

			String jwt = getJwtFromRequest(request);

			if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
				Long userId = tokenProvider.getUserIdFromToken(jwt);

				UserDetails userDetails = myUserDetailsService.loadUserById(userId);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception ex) {
			logger.error("Could not set user authentication in security context", ex);
		}



		filterChain.doFilter(request, response);
	}

	private String getJwtFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader("Authorization");
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
			return bearerToken.substring(7, bearerToken.length());
		}
		return null;
	}
}