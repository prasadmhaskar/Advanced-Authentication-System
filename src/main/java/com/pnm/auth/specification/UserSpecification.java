package com.pnm.auth.specification;

import com.pnm.auth.dto.request.UserFilterRequest;
import com.pnm.auth.domain.entity.User;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

public class UserSpecification {

    public static Specification<User> filter(UserFilterRequest filter) {
        return (root, query, builder) -> {

            Predicate predicate = builder.conjunction();

            if (filter.getKeyword() != null) {
                String kw = "%" + filter.getKeyword().toLowerCase() + "%";
                predicate = builder.and(predicate,
                        builder.or(
                                builder.like(builder.lower(root.get("fullName")), kw),
                                builder.like(builder.lower(root.get("email")), kw)
                        ));
            }

            if (filter.getProviderType() != null) {
                predicate = builder.and(predicate,
                        builder.equal(root.get("authProviderType"), filter.getProviderType()));
            }

            if (filter.getEmailVerified() != null) {
                predicate = builder.and(predicate,
                        builder.equal(root.get("emailVerified"), filter.getEmailVerified()));
            }

            if (filter.getRole() != null) {
                predicate = builder.and(predicate,
                        builder.isMember(filter.getRole(), root.get("roles")));
            }

            return predicate;
        };
    }
}
