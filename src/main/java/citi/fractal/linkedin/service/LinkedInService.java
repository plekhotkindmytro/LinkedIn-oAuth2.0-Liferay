package citi.fractal.linkedin.service;

import org.scribe.builder.ServiceBuilder;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.SignatureType;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import citi.fractal.linkedin.api.config.LinkedInApi20;

import com.liferay.util.portlet.PortletProps;

public class LinkedInService {
	private static final Token EMPTY_REQUEST_TOKEN = null;
	private final String apiKey;
	private final String apiSecret;
	private final String oAuthCallback;
	private OAuthService oAuthService;

	public LinkedInService() {

		apiKey = PortletProps.get("linkedin.api_key");
		apiSecret = PortletProps.get("linkedin.api_secret");
		oAuthCallback = PortletProps.get("linkedin.oauth_callback");
		oAuthService = new ServiceBuilder().provider(LinkedInApi20.class)
				.apiKey(apiKey).apiSecret(apiSecret).callback(oAuthCallback)
				.signatureType(SignatureType.Header).build();
	}

	public String getAuthorizationUrl() {
		return oAuthService.getAuthorizationUrl(EMPTY_REQUEST_TOKEN);
	}

	public String getAccessToken(String code) {
		Verifier verifier = new Verifier(code);
		return oAuthService.getAccessToken(EMPTY_REQUEST_TOKEN, verifier)
				.getToken();
	}

	public void signRequest(Token accessToken, OAuthRequest oauthRequest) {
		oAuthService.signRequest(accessToken, oauthRequest);
	}

	/**
	 * Check: https://developer.linkedin.com/docs/fields/basic-profile
	 * @param accessToken
	 * @return
	 */
	public String getBasicProfile(String accessToken) {
		OAuthRequest oauthRequest = new OAuthRequest(Verb.GET,
				"https://api.linkedin.com/v1/people/~:(picture-url,email-address)?format=json");
		Token token = new Token(accessToken, apiSecret);
		oAuthService.signRequest(token, oauthRequest);
		Response oauthResponse = oauthRequest.send();
		String responseBody = oauthResponse.getBody();
		return responseBody;

	}

}