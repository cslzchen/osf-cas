package io.cos.cas.osf.authentication.support;

/**
 * This is {@link SsoAvailability}, which is used in {@link io.cos.cas.osf.model.OsfInstitution}
 * to map to the types/choices of its counterpart in the OSF model.
 *
 * @author Longze Chen
 * @since 26.1.0
 */
public enum SsoAvailability {

    /**
     * The institution is active, has a delegation protocol, and its SSO setup has been verified.
     * */
    PUBLIC("Public"),
    /**
     * The institution is either: 1) inactive and has a delegation protocol,
     * or 2) active, has a delegation protocol but its SSO setup is in-progress.
     */
    HIDDEN("Hidden"),
    /**
     * The institution does not have a delegation protocol (i.e. not eligible for SSO).
     */
    UNAVAILABLE("Unavailable");

    private final String id;

    SsoAvailability(final String id) {
        this.id = id;
    }

    public static SsoAvailability getType(final String id) throws IllegalArgumentException {
        if (id == null) {
            return null;
        }
        for (final SsoAvailability type : SsoAvailability.values()) {
            if (id.equals(type.getId())) {
                return type;
            }
        }
        throw new IllegalArgumentException("No matching type for id " + id);
    }

    /**
     * @return whether the enum type is {@link SsoAvailability#PUBLIC}.
     */
    public boolean isPublic () {
        return SsoAvailability.PUBLIC.equals(this);
    }

    public boolean isHidden () {
        return SsoAvailability.HIDDEN.equals(this);
    }

    public final String getId() {
        return id;
    }
}
