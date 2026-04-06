package io.cos.cas.osf.authentication.support;

import io.cos.cas.osf.dao.JpaOsfDao;
import io.cos.cas.osf.model.OsfInstitution;

import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * This is {@link OsfInstitutionUtils}, which provides helper methods supporting the institution SSO login flow.
 *
 * @author Longze Chen
 * @since 21.0.0
 */
@Slf4j
public final class OsfInstitutionUtils {

    public final static String ORCID_SUFFIX = " (via ORCiD SSO)";

    /**
     * @param institution the OSF institution to verify
     * @return whether the given institution is eligible for institution SSO.
     */
    public static boolean validateInstitutionForLogin(final OsfInstitution institution) {
        return institution != null
                && institution.getDelegationProtocol() != null
                && institution.getSsoAvailability() != SsoAvailability.UNAVAILABLE;
    }

    /**
     * @param jpaOsfDao the data access object for OSF DB
     * @param institutionId the institution ID
     * @return the institution's support email if exists
     */
    public static String getInstitutionSupportEmail(final JpaOsfDao jpaOsfDao, final String institutionId) {
        final OsfInstitution institution = jpaOsfDao.findOneInstitutionById(institutionId);
        return institution != null ? institution.getSupportEmail() : null;
    }

    /**
     * @param jpaOsfDao the data access object for OSF DB
     * @param target the target query param in shibboleth URL
     * @param institutionId the institution ID used in shortcut SSO mode
     * @return a map of institution name and login URL
     */
    public static Map<String, String> getInstitutionLoginUrlMap(
            final JpaOsfDao jpaOsfDao,
            final String target,
            final String institutionId
    ) {
        List<OsfInstitution> institutionList = new LinkedList<>();
        boolean isShortcutSso = false;
        if (institutionId == null || institutionId.isEmpty()) {
            institutionList = jpaOsfDao.findAllInstitutions();
        } else {
            final OsfInstitution institution = jpaOsfDao.findOneInstitutionById(institutionId);
            if (institution != null) {
                // Must be a valid institution to trigger the shortcut SSO mode
                institutionList.add(institution);
                isShortcutSso = true;
            } else {
                institutionList = jpaOsfDao.findAllInstitutions();
            }
        }
        final Map<String, String> institutionLoginUrlMap = new HashMap<>();
        for (final OsfInstitution institution: institutionList) {
            final SsoAvailability ssoAvailability = institution.getSsoAvailability();
            if (ssoAvailability == null) {
                // Catch a rare exception case where OSF DB has changed the choices of the field
                // `sso_availability` in table `osf_institution` without syncing with CAS.
                LOGGER.error(
                        "Skip instn with invalid SSO avail: [instnId={}]",
                        institution.getInstitutionId()
                );
                continue;
            }
            if (isShortcutSso && ssoAvailability.isHidden()) {
                // Show institutions of hidden SSO Availability in shortcut mode
                LOGGER.debug(
                        "Show instn with hidden SSO avail in shortcut mode: [instnId={}, avail={}]",
                        institution.getInstitutionId(),
                        ssoAvailability.getId()
                );
            } else if (!ssoAvailability.isPublic()) {
                // Hide institutions of non-public SSO Availability
                LOGGER.debug(
                        "Skip instn with non-public SSO avail: [instnId={}, avail={}]",
                        institution.getInstitutionId(),
                        ssoAvailability.getId()
                );
                continue;
            }
            final DelegationProtocol delegationProtocol = institution.getDelegationProtocol();
            if (DelegationProtocol.SAML_SHIB.equals(delegationProtocol)) {
                institutionLoginUrlMap.put(
                        institution.getLoginUrl() + "&target=" + target + '#' + institution.getInstitutionId(),
                        institution.getName()
                );
            } else if (DelegationProtocol.CAS_PAC4J.equals(delegationProtocol)) {
                institutionLoginUrlMap.put(institution.getInstitutionId(), institution.getName());
            } else if (DelegationProtocol.AFFILIATION_VIA_ORCID.equals(delegationProtocol)) {
                institutionLoginUrlMap.put(
                        DelegationProtocol.AFFILIATION_VIA_ORCID.getId() + '#' + institution.getInstitutionId(),
                        institution.getName() + ORCID_SUFFIX
                );
            }
        }
        return institutionLoginUrlMap;
    }

    /**
     * A helper method that sort a map by value instead of key.
     *
     * @param map the map to sort by value
     * @return the sorted map
     */
    public static <K, V extends Comparable<? super V>> Map<K, V> sortByValue(final Map<K, V> map) {
        final List<Map.Entry<K, V>> list = new LinkedList<>(map.entrySet());
        Collections.sort(list, new Comparator<Map.Entry<K, V>>() {
            @Override
            public int compare(final Map.Entry<K, V> e1, final Map.Entry<K, V> e2) {
                return (e1.getValue()).compareTo(e2.getValue());
            }
        });
        final Map<K, V> result = new LinkedHashMap<>();
        for (final Map.Entry<K, V> entry : list) {
            result.put(entry.getKey(), entry.getValue());
        }
        return result;
    }
}
