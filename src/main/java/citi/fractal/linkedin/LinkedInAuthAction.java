package citi.fractal.linkedin;

import java.io.IOException;
import java.util.Calendar;
import java.util.Locale;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import citi.fractal.linkedin.service.LinkedInService;
import citi.fractal.linkedin.session.LinkedInSessionKeys;

import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.exception.SystemException;
import com.liferay.portal.kernel.json.JSONFactoryUtil;
import com.liferay.portal.kernel.json.JSONObject;
import com.liferay.portal.kernel.struts.BaseStrutsAction;
import com.liferay.portal.kernel.util.LocaleUtil;
import com.liferay.portal.kernel.util.ParamUtil;
import com.liferay.portal.kernel.util.StringPool;
import com.liferay.portal.kernel.util.Validator;
import com.liferay.portal.kernel.workflow.WorkflowConstants;
import com.liferay.portal.model.User;
import com.liferay.portal.service.ServiceContext;
import com.liferay.portal.service.UserLocalServiceUtil;
import com.liferay.portal.util.PortalUtil;

public class LinkedInAuthAction extends BaseStrutsAction {

	private LinkedInService linkedInService;

	public LinkedInAuthAction() {
		linkedInService = new LinkedInService();
	}

	private String generateState() {
		return UUID.randomUUID().toString();
	}

	@Override
	public String execute(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		String code = ParamUtil.getString(request, "code");
		if (Validator.isBlank(code)) {
			redirectToLinkedIn(request, response);
			return null;
		}

		if (isCsrfAttack(request)) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return null;
		}

		String accessToken = linkedInService.getAccessToken(code);

		if (Validator.isNotNull(accessToken)) {

			// Uncomment if users are going to use linkedin services manually
			// request.getSession().setAttribute(LinkedInSessionKeys.LINKEDIN_ACCESS_TOKEN,
			// accessToken);
			HttpSession session = request.getSession();
			long companyId = PortalUtil.getCompanyId(request);
			User user = setLinkedInCredentials(companyId, session, accessToken);

			if (user != null
					&& user.getStatus() == WorkflowConstants.STATUS_INCOMPLETE) {
				redirectUpdateAccount(request, response, user);
				return null;
			}

			// is case when user == null is possible?
			response.sendRedirect("/");
			return "";

		} else {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return null;
			/* return "/common/referer_jsp.jsp"; */
		}
	}

	private void redirectUpdateAccount(HttpServletRequest request,
			HttpServletResponse response, User user) {
		// TODO: Redirect to wizard page, right?

	}

	private User setLinkedInCredentials(long companyId, HttpSession session,
			String accessToken) {

		// {
		// "firstName": "Frodo",
		// "headline": "2nd Generation Adventurer",
		// "id": "1R2RtA",
		// "lastName": "Baggins",
		// "siteStandardProfileRequest": {
		// "url": "https://www.linkedin.com/profile/view?id=…"
		// }
		// }

		try {
			String userInfo = linkedInService.getBasicProfile(accessToken);
			JSONObject jsonObject = JSONFactoryUtil.createJSONObject(userInfo);
			String email = jsonObject.getString("email-address");
			User user = UserLocalServiceUtil.getUserByEmailAddress(companyId,
					email);
			if (user == null) {
				user = addUser(session, companyId, jsonObject);
			}

			return user;
		} catch (PortalException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SystemException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	protected User addUser(
			HttpSession session, long companyId, JSONObject jsonObject)
		throws Exception {

		long creatorUserId = 0;
		boolean autoPassword = true;
/*		String password1 = StringPool.BLANK;
		String password2 = StringPool.BLANK;*/
		String password1 = "1234";
		String password2 = "1234";
		boolean autoScreenName = true;
		String screenName = StringPool.BLANK;
		String emailAddress = jsonObject.getString("email");
		long facebookId = jsonObject.getLong("id");
		String openId = StringPool.BLANK;
		Locale locale = LocaleUtil.getDefault();
		String firstName = jsonObject.getString("first_name");
		String middleName = StringPool.BLANK;
		String lastName = jsonObject.getString("last_name");
		int prefixId = 0;
		int suffixId = 0;
		boolean male = Validator.equals(jsonObject.getString("gender"), "male");
		int birthdayMonth = Calendar.JANUARY;
		int birthdayDay = 1;
		int birthdayYear = 1970;
		String jobTitle = StringPool.BLANK;
		long[] groupIds = null;
		long[] organizationIds = null;
		long[] roleIds = null;
		long[] userGroupIds = null;
		boolean sendEmail = true;

		ServiceContext serviceContext = new ServiceContext();
		
		User user = UserLocalServiceUtil.addUser(
			creatorUserId, companyId, autoPassword, password1, password2,
			autoScreenName, screenName, emailAddress, facebookId, openId,
			locale, firstName, middleName, lastName, prefixId, suffixId, male,
			birthdayMonth, birthdayDay, birthdayYear, jobTitle, groupIds,
			organizationIds, roleIds, userGroupIds, sendEmail, serviceContext);

		user = UserLocalServiceUtil.updateLastLogin(
			user.getUserId(), user.getLoginIP());

		user = UserLocalServiceUtil.updatePasswordReset(
			user.getUserId(), false);

		user = UserLocalServiceUtil.updateEmailAddressVerified(
			user.getUserId(), true);

	//	session.setAttribute(WebKeys.FACEBOOK_USER_EMAIL_ADDRESS, emailAddress);

		return user;
	}

	private void redirectToLinkedIn(HttpServletRequest request,
			HttpServletResponse response) throws IOException {
		String url = linkedInService.getAuthorizationUrl();

		// prevent CSRF attack
		final String state = generateState();
		url += "state=" + state;
		request.getSession().setAttribute(LinkedInSessionKeys.LINKEDIN_STATE,
				state);

		response.sendRedirect(url);
	}

	/**
	 * Implement CSRF attack defense using "state" parameter More info here:
	 * https://developer.linkedin.com/docs/oauth2
	 * 
	 * @param request
	 * @return
	 */
	private boolean isCsrfAttack(HttpServletRequest request) {
		HttpSession session = request.getSession();
		String expectedState = (String) session
				.getAttribute(LinkedInSessionKeys.LINKEDIN_STATE);
		session.removeAttribute(LinkedInSessionKeys.LINKEDIN_STATE);

		String actualState = ParamUtil.getString(request, "state");

		return !actualState.equals(expectedState);
	}
}
