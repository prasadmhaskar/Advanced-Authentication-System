package com.pnm.auth.util;

import jakarta.servlet.http.HttpServletRequest;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IpUtilsTest {

    @Test
    void getClientIpUsesFirstForwardedForEntry() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Forwarded-For"))
                .thenReturn("203.0.113.5, 70.41.3.18, 150.172.238.178");
        Mockito.when(request.getRemoteAddr()).thenReturn("192.0.2.10");

        String ip = IpUtils.getClientIp(request);

        assertThat(ip).isEqualTo("203.0.113.5");
    }

    @Test
    void getClientIpFallsBackWhenForwardedForMissing() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        Mockito.when(request.getRemoteAddr()).thenReturn("198.51.100.22");

        String ip = IpUtils.getClientIp(request);

        assertThat(ip).isEqualTo("198.51.100.22");
    }

    @Test
    void getClientIpFallsBackWhenForwardedForUnknown() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Forwarded-For")).thenReturn("unknown");
        Mockito.when(request.getRemoteAddr()).thenReturn("198.51.100.55");

        String ip = IpUtils.getClientIp(request);

        assertThat(ip).isEqualTo("198.51.100.55");
    }

    @Test
    void getClientIpFallsBackWhenForwardedForInvalidLength() {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        Mockito.when(request.getHeader("X-Forwarded-For"))
                .thenReturn("1234:1234:1234:1234:1234:1234:1234:1234:1234:1234:1234");
        Mockito.when(request.getRemoteAddr()).thenReturn("203.0.113.10");

        String ip = IpUtils.getClientIp(request);

        assertThat(ip).isEqualTo("203.0.113.10");
    }

    @Test
    void isPrivateIpDetectsPrivateAndLocalAddresses() {
        assertThat(IpUtils.isPrivateIp("10.0.0.1")).isTrue();
        assertThat(IpUtils.isPrivateIp("127.0.0.1")).isTrue();
        assertThat(IpUtils.isPrivateIp("169.254.0.1")).isTrue();
    }

    @Test
    void isPrivateIpReturnsFalseForPublicAndInvalidAddresses() {
        assertThat(IpUtils.isPrivateIp("8.8.8.8")).isFalse();
        assertThat(IpUtils.isPrivateIp("not-an-ip")).isFalse();
    }

    @Test
    void constructorThrowsUnsupportedOperationException() throws Exception {
        Constructor<IpUtils> constructor = IpUtils.class.getDeclaredConstructor();
        constructor.setAccessible(true);

        InvocationTargetException thrown = assertThrows(InvocationTargetException.class, constructor::newInstance);

        assertThat(thrown.getCause())
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessage("Utility class cannot be instantiated");
    }
}

