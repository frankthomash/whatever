package de.swisslife.koala.userclient.security;

import de.swisslife.esb.services.dataobjects.orga.OrgaBenutzerDO;
import de.swisslife.koala.userclient.service.security.SecurityService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class KoalaUserDetailsAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

  private static final Logger LOG = LogManager.getLogger();


  @Autowired
  private SecurityService securityService;

  @Override
  protected void additionalAuthenticationChecks(UserDetails userDetails,
      UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
  }

  @Override
  protected UserDetails retrieveUser(String username,
      UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    String password = (String) authentication.getCredentials();
    boolean authenticated;
    try {
      authenticated = securityService.anmelden(username, password);
    } catch (Exception te) {
      LOG.error("Anmeldung fehlgeschlagen!", te);
      throw new AuthenticationTechnicalException("Anmeldung fehlgeschlagen!", te);
    }
    if (!authenticated) {
      throw new BadCredentialsException("Benutzername und Passwort passen nicht zueinander.");
    }
    return erstelleBenutzer(username, password);
  }

  /**
   * Erstellt einen {@code Benutzer} Objekt mit angegebenem Benutzername und Passwort und dessen LEGI-Rollen
   * (Authorities).
   *
   * @param benutzerName
   * @param passwort
   * @return
   */
  public Benutzer erstelleBenutzer(final String benutzerName, final String passwort) {
    try {
      OrgaBenutzerDO benutzerDO = securityService.ladeBenutzerDetails(benutzerName);
      Benutzer benutzer = new Benutzer(benutzerName, passwort, benutzerDO);
      List<String> authorities = securityService.ladeKoalaRechte(benutzerName);
      List<String> allgemeineRechte = securityService.ladeAllgemeineRechte(benutzerName);
      benutzer.buildAuthorities(authorities);
      benutzer.buildAuthorities(allgemeineRechte);
      LOG.info(
          "Der Benutzer '{}' wurde authentifiziert, seine LEGI-Rechte wurden geladen und steht nun für die Autorisierungsprüfung bereit.",
          benutzerName);
      return benutzer;
    } catch (Exception t) {
      throw new AuthenticationTechnicalException(
          "Ermittlung der Anwenderdaten und Rechte fehlgeschlagen", t);
    }
  }

}
