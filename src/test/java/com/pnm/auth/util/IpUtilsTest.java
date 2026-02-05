package com.pnm.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IpUtilsTest {

    @Test
    @DisplayName("Should return remote addr directly (delegating trust to Spring/Container)")
    void shouldReturnRemoteAddr() {
        // Given
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getRemoteAddr()).thenReturn("203.0.113.195");

        // When
        String ip = IpUtils.getClientIp(request);

        // Then
        assertEquals("203.0.113.195", ip);
    }
}