package com.pnm.auth.service.impl.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.pnm.auth.domain.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {

    private Long id;
    private String email;

    @JsonIgnore
    private String password;

    private boolean active;
    private Integer tokenVersion;
    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.active = user.isActive();
        this.tokenVersion = user.getTokenVersion();

        // FIX: Directly map the role. Do NOT append "ROLE_" if DB already has it.
        this.authorities = user.getRoles().stream()
                .map(role -> {
                    // Safety check: Ensure it starts with ROLE_ to satisfy Spring standards
                    if (role.startsWith("ROLE_")) {
                        return new SimpleGrantedAuthority(role);
                    } else {
                        return new SimpleGrantedAuthority("ROLE_" + role);
                    }
                })
                .toList();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override public boolean isAccountNonLocked() { return active; }
    @Override public boolean isEnabled() { return active; }
}