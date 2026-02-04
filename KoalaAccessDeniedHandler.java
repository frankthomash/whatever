package de.swisslife.koala.userclient.security;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class KoalaAccessDeniedHandler implements AccessDeniedHandler, KoalaSecurityConstants {

  private static final Logger LOG = LogManager.getLogger();

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException accessDeniedException) throws IOException, ServletException {
    LOG.info("Der Benutzer ist nicht berechtigt auf diese Seite '{}' zuzugreifen", request.getRequestURI());
    HttpSession oldSession = request.getSession(false);
    if (oldSession != null) {
      oldSession.invalidate();
    }
    HttpSession newsession = request.getSession(true);
    newsession.setAttribute(SESSION_LOGIN_PARAM, KEY_AUTHORIZATION_ERROR);
    LOG.error("Weiterleitung zu login.jsp wegen AccessdeniedException");
    response.sendRedirect(request.getContextPath() + "/login.jsp");
  }

}
