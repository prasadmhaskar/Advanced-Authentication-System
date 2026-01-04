package com.pnm.auth.dto.request;

import java.time.LocalDateTime;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Filter criteria for login activities")
public class LoginActivityFilterRequest {

    @Schema(description = "Exact User ID to filter history", example = "1")
    private Long userId;

    @Schema(description = "Search by Email or IP Address", example = "john@example.com")
    private String search;

    @Schema(description = "Filter by Success/Failure status", example = "false")
    private Boolean success;

    @Schema(description = "Filter records after this date (YYYY-MM-DDTHH:mm:ss)", example = "2024-01-01T00:00:00")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime startDate;

    @Schema(description = "Filter records before this date (YYYY-MM-DDTHH:mm:ss)", example = "2024-12-31T23:59:59")
    @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
    private LocalDateTime endDate;
}

