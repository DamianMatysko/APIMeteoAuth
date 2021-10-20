package com.meteoauth.MeteoAuth.oauth2;

import com.meteoauth.MeteoAuth.dto.OAuth2UserInfo;
import com.meteoauth.MeteoAuth.entities.GoogleUser;
import com.meteoauth.MeteoAuth.entities.User;
import com.meteoauth.MeteoAuth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;


import java.util.Map;
import java.util.Optional;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if(registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException("Sorry! Login with " + registrationId + " is not supported yet.");
        }
    }

    @Service
    public static class OAuth2UserService extends DefaultOAuth2UserService {

            @Autowired
            private UserRepository userRepository; //todo different UserREP


        @Override
            public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) {
                OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

                try {
                    return processOAuth2User(oAuth2UserRequest, oAuth2User);
                } catch (AuthenticationException ex) {
                    throw ex;
                } catch (Exception ex) {
                    // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
                    throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
                }
            }

            private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
                OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
                if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
                    throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
                }

                Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
                GoogleUser googleUser;
                if(userOptional.isPresent()) {
                    googleUser = userOptional.get();
                    if(!googleUser.getProvider().equals(java.security.AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
                        throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
                                googleUser.getProvider() + " account. Please use your " + googleUser.getProvider() +
                                " account to login.");
                    }
                    googleUser = updateExistingUser(googleUser, oAuth2UserInfo);
                } else {
                    googleUser = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
                }

                return UserPrincipal.create(googleUser, oAuth2User.getAttributes());
            }

            private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
                User user = new User();

                user.setProvider(java.security.AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
                user.setProviderId(oAuth2UserInfo.getId());
                user.setName(oAuth2UserInfo.getName());
                user.setEmail(oAuth2UserInfo.getEmail());
                user.setImageUrl(oAuth2UserInfo.getImageUrl());
                return userRepository.save(user);
            }

            private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
                existingUser.setName(oAuth2UserInfo.getName());
                existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
                return userRepository.save(existingUser);
            }

        }
}