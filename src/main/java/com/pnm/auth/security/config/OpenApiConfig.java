//package com.pnm.auth.security.config;
//
//import com.pnm.auth.web.context.RequestContext;
//import io.swagger.v3.oas.annotations.OpenAPIDefinition;
//import io.swagger.v3.oas.annotations.info.Contact;
//import io.swagger.v3.oas.annotations.info.Info;
//import io.swagger.v3.oas.annotations.servers.Server;
//import io.swagger.v3.oas.models.Components;
//import io.swagger.v3.oas.models.OpenAPI;
//import io.swagger.v3.oas.models.security.SecurityRequirement;
//import io.swagger.v3.oas.models.security.SecurityScheme;
//import org.springdoc.core.utils.SpringDocUtils;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//@OpenAPIDefinition(
//        info = @Info(
//                contact = @Contact(
//                        name = "Prasad Mhaskar",
//                        email = "prasad@example.com"
//                ),
//                description = "Advanced Authentication System API Documentation",
//                title = "Auth System API",
//                version = "1.0"
//        ),
//        servers = {
//                @Server(
//                        description = "Local Environment",
//                        url = "http://localhost:8080"
//                )
//        }
//)
//public class OpenApiConfig {
//    static {
//        // This hides RequestContext from Swagger UI globally
//        SpringDocUtils.getConfig().addRequestWrapperToIgnore(RequestContext.class);
//    }
//
//    @Bean
//    public OpenAPI customOpenAPI() {
//        final String securitySchemeName = "BearerAuth";
//
//        return new OpenAPI()
//                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
//                .components(new Components()
//                        .addSecuritySchemes(securitySchemeName,
//                                new SecurityScheme()
//                                        .name(securitySchemeName)
//                                        .type(SecurityScheme.Type.HTTP)
//                                        .scheme("bearer")
//                                        .bearerFormat("JWT")
//                        ));
//    }
//}

//package com.pnm.auth.security.config;
//
//import com.pnm.auth.web.context.RequestContext;
//import io.swagger.v3.oas.annotations.OpenAPIDefinition;
//import io.swagger.v3.oas.annotations.info.Contact;
//import io.swagger.v3.oas.annotations.info.Info;
//import io.swagger.v3.oas.annotations.servers.Server;
//import io.swagger.v3.oas.models.Components;
//import io.swagger.v3.oas.models.OpenAPI;
//import io.swagger.v3.oas.models.security.SecurityRequirement;
//import io.swagger.v3.oas.models.security.SecurityScheme;
//import org.springdoc.core.utils.SpringDocUtils;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//@OpenAPIDefinition(
//        info = @Info(
//                contact = @Contact(
//                        name = "Prasad Mhaskar",
//                        email = "prasadmhaskar33@gmail.com"
//                ),
//                description = """
//                        ## Advanced Authentication System API
//
//                        **Production Ready Authentication Service** with JWT, OAuth2, and Risk Analysis.
//
//                        ### 🔐 Quick Login (OAuth2)
//                        Since there is no frontend, use these links to generate tokens:
//
//                        * <a href="/oauth2/authorization/google" target="_blank">Login with Google</a>
//                        * <a href="/oauth2/authorization/github" target="_blank">Login with GitHub</a>
//
//                        **Instructions:**
//                        1. Click a link above to login.
//                        2. Copy the `accessToken` from the JSON response.
//                        3. Click the **Authorize** button below.
//                        4. Paste the token into the `BearerAuth` box.
//                        """,
//                title = "Auth System API",
//                version = "1.0"
//        ),
//        servers = {
//                @Server(
//                        description = "Current Environment",
//                        url = "/"
//                )
//        }
//)
//public class OpenApiConfig {
//    static {
//        // This hides RequestContext from Swagger UI globally
//        SpringDocUtils.getConfig().addRequestWrapperToIgnore(RequestContext.class);
//    }
//
//    @Bean
//    public OpenAPI customOpenAPI() {
//        final String securitySchemeName = "BearerAuth";
//
//        return new OpenAPI()
//                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
//                .components(new Components()
//                        .addSecuritySchemes(securitySchemeName,
//                                new SecurityScheme()
//                                        .name(securitySchemeName)
//                                        .type(SecurityScheme.Type.HTTP)
//                                        .scheme("bearer")
//                                        .bearerFormat("JWT")
//                        ));
//    }
//}


package com.pnm.auth.security.config;

import com.pnm.auth.web.context.RequestContext;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.utils.SpringDocUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                contact = @Contact(
                        name = "Prasad Mhaskar",
                        email = "your.real.email@example.com",
                        url = "https://www.linkedin.com/in/your-profile"
                ),
                description = """
                        ## 🚀 Advanced Authentication System
                        
                        **Enterprise-grade Identity Provider** demonstrating high-concurrency handling, distributed security, and resilience patterns.
                        
                        ---
                        
                        ### 🧪 Test Credentials (Live Demo)
                        Use these accounts to test the API immediately.
                        But for testing other APIs like (email verification, OTP verification) i recommend you to register using your email or temp email.
                        
                        | Role | Email | Password | Access |
                        | :--- | :--- | :--- | :--- |
                        | **Admin** | `admin@demo.com` | `Admin@123` | Full Access + `/api/admin/**` |
                        | **User** | `user@demo.com` | `User@123` | Standard Access |
                        
                        > **Note:** Data in these accounts may be reset periodically.
                        
                        ---
                        
                        ### 🏗️ Architecture Highlights
                        * **Security:** JWT (RS256/HS512), OAuth2 (Google/GitHub), Role-Based Access Control (RBAC).
                        * **Resilience:** `Resilience4j` Circuit Breakers & Retries for external services (Email, IP Risk).
                        * **Concurrency:** Redis-based locking and polling for Race Condition handling.
                        * **Performance:** Async Event-Driven Architecture for non-blocking audits and notifications.
                        
                        ---
                        
                        ### 🔐 Quick Login (OAuth2)
                        * <a href="/oauth2/authorization/google" target="_blank">Login with Google</a>
                        * <a href="/oauth2/authorization/github" target="_blank">Login with GitHub</a>
                        """,
                title = "Advanced Auth System API",
                version = "1.0"
        ),
        servers = {
                @Server(description = "Current Environment", url = "/")
        }
)
public class OpenApiConfig {
    static {
        SpringDocUtils.getConfig().addRequestWrapperToIgnore(RequestContext.class);
    }

    @Bean
    public OpenAPI customOpenAPI() {
        final String securitySchemeName = "BearerAuth";

        return new OpenAPI()
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName))
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                        ));
    }
}
