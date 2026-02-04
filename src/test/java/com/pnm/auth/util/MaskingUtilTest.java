package com.pnm.auth.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MaskingUtilTest {

    @Test
    void returnsUnknownForNullEmail() {
        assertThat(MaskingUtil.maskEmail(null)).isEqualTo("UNKNOWN");
    }

    @Test
    void returnsUnknownForEmptyEmail() {
        assertThat(MaskingUtil.maskEmail("")).isEqualTo("UNKNOWN");
    }

    @Test
    void masksShortLocalPartEmails() {
        assertThat(MaskingUtil.maskEmail("a@domain.com")).isEqualTo("****@domain.com");
    }

    @Test
    void masksLongerEmailsUsingFirstAndLastLocalCharacters() {
        assertThat(MaskingUtil.maskEmail("ab@domain.com")).isEqualTo("a***b@domain.com");
        assertThat(MaskingUtil.maskEmail("alice@example.com")).isEqualTo("a***e@example.com");
    }
}
