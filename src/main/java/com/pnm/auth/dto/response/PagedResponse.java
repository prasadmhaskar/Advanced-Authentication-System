package com.pnm.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Page;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PagedResponse<T> {

    @Schema(description = "The actual data items for the current page")
    private List<T> content;
    @Schema(description = "Current page number (0-indexed)", example = "0")
    private int page;
    @Schema(description = "Number of items per page", example = "10")
    private int size;
    @Schema(description = "Total number of items available across all pages", example = "100")
    private long totalElements;
    @Schema(description = "Total number of available pages", example = "10")
    private int totalPages;
    @Schema(description = "Indicates if this is the last page", example = "false")
    private boolean last;

    public static <T> PagedResponse<T> of(Page<T> page) {
        return PagedResponse.<T>builder()
                .content(page.getContent())
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .last(page.isLast())
                .build();
    }
}
