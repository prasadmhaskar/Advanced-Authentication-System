package com.pnm.auth.service.admin;

import com.pnm.auth.dto.request.LoginActivityFilterRequest;
import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.dto.response.LoginActivityResponse;
import com.pnm.auth.dto.response.PagedResponse;
import com.pnm.auth.dto.response.UserAdminResponse;
import com.pnm.auth.service.impl.admin.AdminServiceImpl;

public interface AdminService {

    PagedResponse<UserAdminResponse> getUsers(int page, int size, UserFilterRequest filter);
    void deleteUser(Long id);
    AdminServiceImpl.BlockUserResult blockUser(Long id);
    AdminServiceImpl.UnblockUserResult unblockUser(Long id);
    PagedResponse<LoginActivityResponse> getLoginActivities(int page, int size, LoginActivityFilterRequest filter);
    LoginActivityResponse getActivityById(Long id);
}
