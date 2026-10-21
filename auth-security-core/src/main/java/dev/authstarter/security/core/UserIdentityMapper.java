package dev.authstarter.security.core;

import org.springframework.security.core.userdetails.UserDetails;

/** Maps a Spring Security principal to the starter's minimal identity without imposing an application user model. */
@FunctionalInterface
public interface UserIdentityMapper {

    AuthenticatedUser map(UserDetails userDetails);
}
