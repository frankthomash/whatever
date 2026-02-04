package de.swisslife.versandsteuerung.security;

import de.swisslife.esb.services.responseobjects.authentisierung.AuthActiveDirectoryResponseDO;
import de.swisslife.versandsteuerung.esbclient.AuthentisierungsServiceAdapter;
import de.swisslife.versandsteuerung.esbclient.LegiInfoServiceAdapter;
import de.swisslife.versandsteuerung.exceptions.FachlicherFehler;
import de.swisslife.versandsteuerung.exceptions.FachlicherFehlerCode;
import de.swisslife.versandsteuerung.exceptions.VersandsteuerungFehler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.apache.commons.lang3.StringUtils.isEmpty;

@Service
public class BenutzerServiceImpl implements BenutzerService {

	private static final Logger LOGGER = LoggerFactory.getLogger(BenutzerServiceImpl.class);

	@Autowired
	AuthentisierungsServiceAdapter authService;
	@Autowired
	LegiInfoServiceAdapter legiInfoService;

	@Override
	public User anmelden(String username, String password) {
		LOGGER.info("Anmeldung für Benutzer " + username);

		try {

			// 1. Authentifizierung
			if (!isEmpty(username) && !isEmpty(password)) {
				LOGGER.debug("Formular Login: Authentifizierung über ESB wird aufgerufen.");
				AuthActiveDirectoryResponseDO response = authService.authActiveDirectory(username, password);

				// 2. Autorisierung
				if (response.isAuthentisiert()) {
					LOGGER.debug("Benutzer wurde authentifiziert. Prüfung der Berechtigungen erfolgt.");

					// Abfragen welche Berechtigungen der Anwender besitzt
					List<GrantedAuthority> granted = new ArrayList<>();
					for (Authority auth : Authority.values()) {
						if (legiInfoService.pruefeAttributRecht(username, auth.name()).isSuccess()) {
							LOGGER.debug("Benutzer wurde die Berechtigung " + auth.name() + " gewährt.");
							granted.add(new SimpleGrantedAuthority(auth.name()));
						}
					}
					return new User(username, password, granted);
				} else {
					throw new BadCredentialsException("Benutzername oder Passwort falsch.");
				}
			} else {
				// wird eigentlich schon in der WebSecurityConfig abgefangen, aber sicher ist
				// sicher...
				throw new AuthenticationCredentialsNotFoundException(
						"Benutzername und Password dürfen nicht leer sein.");
			}
		} catch (FachlicherFehler fehler) {
			if(FachlicherFehlerCode.FACHLICHER_ESB_FEHLER.getCode().equals(fehler.getCode())) {
				Pattern pattern = Pattern.compile("(?<=\\[)([^\\[\\]]+)(?=\\])");  // alles innerhalb [ und ]
				Matcher matcher = pattern.matcher(fehler.getMessage());
				List<String> nachrichten = new ArrayList<>();
				while(matcher.find()) {
				    nachrichten.add(matcher.group(1));
				}
				String asHtml = nachrichten.stream().collect(Collectors.joining("</br>"));
				throw new BadCredentialsException(asHtml);	
			} else {
				throw new AuthenticationServiceException("Unerwarteter Fehler beim Login.", fehler);
			}
		} catch (VersandsteuerungFehler fehler) {
			throw new AuthenticationServiceException("Unerwarteter Fehler beim Login.", fehler);
		}
	}

}