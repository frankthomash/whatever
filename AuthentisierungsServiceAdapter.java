package de.swisslife.versandsteuerung.esbclient;

import de.swisslife.esb.services.requestobjects.RequestContext;
import de.swisslife.esb.services.responseobjects.BaseServiceResponse;
import de.swisslife.esb.services.responseobjects.authentisierung.AuthActiveDirectoryResponseDO;
import de.swisslife.esb.services.ws.authentisierungsservice.AuthentisierungsServiceWS;
import de.swisslife.versandsteuerung.exceptions.ExtendedResourceBundleMessageSource;
import de.swisslife.versandsteuerung.exceptions.VersandsteuerungFehler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class AuthentisierungsServiceAdapter {

	@Autowired
	private WSFactory wsFactory;

	@Autowired
	private ExtendedResourceBundleMessageSource extendedResourceBundleMessageSource;

	public AuthActiveDirectoryResponseDO authActiveDirectory(final String userId, final String passwd)
			throws VersandsteuerungFehler {

		return (AuthActiveDirectoryResponseDO) new EsbAdapter(extendedResourceBundleMessageSource) {
			@Override
			public BaseServiceResponse callWSOperation() throws VersandsteuerungFehler {
				RequestContext requestContext = wsFactory.createRequestContext(userId);
				AuthentisierungsServiceWS authentisierungsServiceWS = wsFactory.getAuthentisierungsServiceWS();
				BaseServiceResponse response = authentisierungsServiceWS.authActiveDirectory(requestContext, passwd);
				return response;
			};

			@Override
			public void refreshWSInCache() {
				wsFactory.refreshAuthentisierungsServiceWSInCache();
			}
		}.execute();
	}

}
