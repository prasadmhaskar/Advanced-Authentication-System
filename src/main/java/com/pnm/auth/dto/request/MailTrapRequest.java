package com.pnm.auth.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class MailTrapRequest {
    private EmailAddress from;
    private List<EmailAddress> to;
    private String subject;
    private String text;   // Plain text version
    private String html;   // HTML version
    private String category;

    // Optional: Custom variables for templates
    @JsonProperty("custom_variables")
    private Map<String, String> customVariables;

    @Data
    @Builder
    public static class EmailAddress {
        private String email;
        private String name;
    }
}
