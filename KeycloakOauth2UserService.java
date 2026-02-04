package de.swisslife.koala.userclient.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Component
@Slf4j
@RequiredArgsConstructor
public class KeycloakOauth2UserService extends OidcUserService {

  private final KoalaUserDetailsAuthenticationProvider koalaUserDetailsAuthenticationProvider;

  /**
   * Augments {@link OidcUserService#loadUser(OidcUserRequest)} to add authorities
   * provided by Keycloak.
   * <p>
   * Needed because {@link OidcUserService#loadUser(OidcUserRequest)} (currently)
   * does not provide a hook for adding custom authorities from a
   * {@link OidcUserRequest}.
   */
  @Override
  public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

    OidcUser user = super.loadUser(userRequest);
    String username = user.getAttribute("preferred_username");
    Benutzer principle = koalaUserDetailsAuthenticationProvider.erstelleBenutzer(username, username);

    Set<GrantedAuthority> authorities = new LinkedHashSet<>();
    authorities.addAll(principle.getAuthorities());

    Map<String, Object> claims = new HashMap<>();
    claims.put("benutzer", principle);
    return new DefaultOidcUser(authorities, userRequest.getIdToken(), new OidcUserInfo(claims), "preferred_username");
  }

}
