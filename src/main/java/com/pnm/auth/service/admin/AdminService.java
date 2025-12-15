package com.pnm.auth.service.admin;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;

public interface AdminService {

    PagedResponse<UserAdminResponse> getUsers(int page, int size, UserFilterRequest filter);
    void deleteUser(Long id);
    void blockUser(Long id);
    void unblockUser(Long id);
    PagedResponse<LoginActivityResponse> getLoginActivities(int page, int size, LoginActivityFilterRequest filter);
    LoginActivityResponse getActivityById(Long id);
}
