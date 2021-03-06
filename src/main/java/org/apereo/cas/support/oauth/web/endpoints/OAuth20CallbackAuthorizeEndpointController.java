package org.apereo.cas.support.oauth.web.endpoints;

import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.authenticator.Authenticators;

import io.cos.cas.oauth.support.OsfCasOAuth20Constants;
import io.cos.cas.oauth.support.OsfCasOAuth20ModelContext;
import io.cos.cas.oauth.support.OsfCasOAuth20Utils;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import org.apache.commons.lang3.StringUtils;

import org.pac4j.core.context.JEEContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.engine.DefaultCallbackLogic;
import org.pac4j.core.exception.http.HttpAction;
import org.pac4j.core.exception.http.WithLocationAction;
import org.pac4j.core.profile.ProfileManager;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * OAuth callback authorize controller based on the pac4j callback controller.
 *
 * @author Jerome Leleu
 * @author Longze Chen
 * @since 3.5.0
 */
@Slf4j
public class OAuth20CallbackAuthorizeEndpointController extends BaseOAuth20Controller {

    public OAuth20CallbackAuthorizeEndpointController(final OAuth20ConfigurationContext oAuthConfigurationContext) {
        super(oAuthConfigurationContext);
    }

    /**
     * Handle request.
     *
     * @param request  the request
     * @param response the response
     * @return the model and view
     */
    @GetMapping(path = {
            OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.CALLBACK_AUTHORIZE_URL,
            OAuth20Constants.BASE_OAUTH20_URL + '/' + OAuth20Constants.CALLBACK_AUTHORIZE_URL + '/',

    })
    public ModelAndView handleRequest(final HttpServletRequest request, final HttpServletResponse response) {

        val modelContext = new OsfCasOAuth20ModelContext();

        val callback = new OAuth20CallbackLogic();
        val context = new JEEContext(request, response, getOAuthConfigurationContext().getSessionStore());
        // Build the request URL with server prefix "https://accounts.osf.io" instead of calling `context.getFullRequestURL()` which
        // somehow uses "https://127.0.0.1". This is a work-around for a weird tomcat relative redirect issue on staging 1 and prod.
        val serverPrefix = getOAuthConfigurationContext().getCasProperties().getServer().getPrefix();
        val fullRequestUrl = serverPrefix + request.getRequestURI() + '?' + request.getQueryString();
        LOGGER.debug("[OAuth callbackAuthorize] full request URL in context [{}]", context.getFullRequestURL());
        LOGGER.debug("[OAuth callbackAuthorize] full request URL customized [{}]", fullRequestUrl);
        callback.perform(
                context,
                getOAuthConfigurationContext().getOauthConfig(), (object, ctx) -> Boolean.FALSE,
                fullRequestUrl,
                Boolean.TRUE,
                Boolean.FALSE,
                Boolean.FALSE,
                Authenticators.CAS_OAUTH_CLIENT
        );
        var url = callback.getRedirectUrl();
        if (!url.startsWith(serverPrefix)) {
            LOGGER.warn("[OAuth callbackAuthorize] redirect URL [{}] doesn't have the correct server prefix [{}]", url, serverPrefix);
            try {
                URI uri = new URI(url);
                url = serverPrefix + uri.getPath() + '?' + uri.getRawQuery();
                LOGGER.warn("[OAuth callbackAuthorize] use server prefix for redirect URL [{}]", url);
            } catch (URISyntaxException e) {
                modelContext.setErrorCode(OsfCasOAuth20Constants.INTERNAL_SERVER_ERROR);
                modelContext.setErrorMsg(e.getMessage());
                modelContext.setOsfUrl(getOsfUrl());
                return OsfCasOAuth20Utils.produceOAuth20ErrorView(modelContext);
            }
        } else {
            LOGGER.info("[OAuth callbackAuthorize] redirect URL [{}] uses the correct server prefix: [{}}]", url, serverPrefix);
        }
        if (StringUtils.isBlank(url)) {
            modelContext.setErrorCode(OsfCasOAuth20Constants.SESSION_STALE_MISMATCH);
            LOGGER.error(modelContext.getErrorMsg());
            modelContext.setErrorMsg("Unable to locate OAuth redirect URL from the session store; Stale or mismatched session request?");
            modelContext.setOsfUrl(getOsfUrl());
            return OsfCasOAuth20Utils.produceOAuth20ErrorView(modelContext);
        }
        val manager = new ProfileManager<>(context, context.getSessionStore());
        LOGGER.debug("OAuth callback URL is [{}]", url);
        return getOAuthConfigurationContext().getCallbackAuthorizeViewResolver().resolve(context, manager, url);
    }

    @Getter
    private static class OAuth20CallbackLogic extends DefaultCallbackLogic {

        private String redirectUrl;

        @Override
        protected HttpAction redirectToOriginallyRequestedUrl(final WebContext context, final String defaultUrl) {
            val result = getSavedRequestHandler().restore(context, defaultUrl);
            if (result instanceof WithLocationAction) {
                redirectUrl = WithLocationAction.class.cast(result).getLocation();
            }
            return result;
        }
    }
}
