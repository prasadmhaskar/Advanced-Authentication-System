package com.pnm.auth.service;

import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.entity.User;

import java.util.List;

public interface AdminService {

    PagedResponse<UserAdminResponse> getUsers(int page, int size, UserFilterRequest filter);
    void deleteUser(Long id);
    void blockUser(Long id);
    void unblockUser(Long id);
}
