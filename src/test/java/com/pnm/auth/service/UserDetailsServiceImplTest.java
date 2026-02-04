package com.pnm.auth.service;

import com.pnm.auth.domain.entity.User;
import com.pnm.auth.repository.UserRepository;
import com.pnm.auth.service.impl.user.UserDetailsImpl;
import com.pnm.auth.service.impl.user.UserDetailsServiceImpl;
import com.pnm.auth.util.MaskingUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    @Test
    @DisplayName("loadUserByUsername returns UserDetailsImpl with mapped authorities")
    void loadUserByUsername_ReturnsUserDetails() {
        String email = "user@example.com";
        User user = new User();
        user.setId(42L);
        user.setEmail(email);
        user.setPassword("hashed");
        user.setActive(true);
        user.setTokenVersion(3);
        user.setRoles(List.of("ROLE_ADMIN", "USER"));

        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
        Set<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        assertAll(
                () -> assertInstanceOf(UserDetailsImpl.class, userDetails),
                () -> assertEquals(email, userDetails.getUsername()),
                () -> assertEquals("hashed", userDetails.getPassword()),
                () -> assertEquals(Set.of("ROLE_ADMIN", "ROLE_USER"), authorities)
        );
        verify(userRepository).findByEmail(email);
    }

    @Test
    @DisplayName("loadUserByUsername throws when user is missing")
    void loadUserByUsername_ThrowsWhenMissing() {
        String email = "missing@example.com";
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(email)
        );

        assertEquals(
                "User not found with email: " + MaskingUtil.maskEmail(email),
                exception.getMessage()
        );
        verify(userRepository).findByEmail(email);
    }
}

