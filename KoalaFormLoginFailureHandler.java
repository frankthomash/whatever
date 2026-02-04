package de.swisslife.koala.userclient.security;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class KoalaFormLoginFailureHandler
    implements AuthenticationFailureHandler, KoalaSecurityConstants {

  private static final Logger LOG = LogManager.getLogger();
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException exception) throws IOException, ServletException {

    HttpSession session = request.getSession();
    if (exception instanceof AuthenticationTechnicalException) {
      session.setAttribute(SESSION_LOGIN_PARAM, KEY_TECHNICAL_ERROR);
      LOG.error("Weiterleitung zu login.jsp wegen technical error");
    } else {
      session.setAttribute(SESSION_LOGIN_PARAM, KEY_AUTHENTICATION_ERROR);
      LOG.error("Weiterleitung zu login.jsp wegen authentication error");
    }
    response.sendRedirect(request.getContextPath() + "/login.jsp");
  }

}
