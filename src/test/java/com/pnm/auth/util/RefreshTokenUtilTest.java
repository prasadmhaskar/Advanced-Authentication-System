package com.pnm.auth.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenUtilTest {

    private final RefreshTokenUtil refreshTokenUtil = new RefreshTokenUtil();

    @Test
    void generatesOpaqueRandomTokensAndStableHashes() {
        String first = refreshTokenUtil.generateToken();
        String second = refreshTokenUtil.generateToken();

        assertThat(first).hasSize(43).isNotEqualTo(second);
        assertThat(refreshTokenUtil.hash(first)).hasSize(64);
        assertThat(refreshTokenUtil.hash(first)).isEqualTo(refreshTokenUtil.hash(first));
        assertThat(refreshTokenUtil.hash(first)).isNotEqualTo(first);
    }
}
