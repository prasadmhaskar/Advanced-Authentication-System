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
                        email = "prasadmhaskar33@gmail.com",
                        url = "https://www.linkedin.com/in/prasad-mhaskar/"
                ),
                description = """
                        ## 🚀 Advanced Authentication & Security Platform
                        
                        **A Hardened, Zero-Trust Identity Provider (IdP)** engineered for high-concurrency, distributed security, and resilience.
                        
                        ---
                        
                        ### 🛠️ Architectural Design: Headless Security
                        This system operates on an **API-First** architecture.
                        * **Transparency:** Provides direct visibility into critical security mechanisms (HttpOnly cookies, JWT payloads, Security Headers) often abstracted by frontends.
                        * **Validation:** Allows reviewers to validate the raw API contract and strict security implementation directly.
                        
                        ---
                        
                        ### 🏗️ Core Features
                        * **🛡️ Defense-in-Depth:** Nginx Rate Limiting (L7) + Redis Bucket4j (App Layer).
                        * **🔐 Identity:** Stateless JWT (RS256) with Rotation & OAuth2 (Google/GitHub).
                        * **🤖 Risk Engine:** Adaptive behavioral analysis based on IP reputation & Device Fingerprinting.
                        * **⚡ Performance:** Async Event-Driven architecture using Virtual Threads.
                        
                        ---
                        
                        ### 🧪 Live Testing Credentials
                        > **Recommendation:** To test **MFA & Email Verification**, please register a new account via the `/api/auth/register` endpoint.
                        
                        | Role | Username / Email | Password | Scope |
                        | :--- | :--- | :--- | :--- |
                        | **Admin** | `admin@demo.com` | `Admin@123` | User Management & Analytics |
                        | **User** | `user@demo.com` | `User@123` | Profile & Standard Access |
                        
                        ---
                        
                        ### 🔗 Quick Actions (OAuth2)
                        * [**Login with Google**](/oauth2/authorization/google)
                        * [**Login with GitHub**](/oauth2/authorization/github)
                        * [**View Source Code (GitHub)**](https://github.com/prasadmhaskar/Advanced-Authentication-System)
                        """,
                title = "Advanced Auth System API",
                version = "1.0"
        ),
        servers = {
                @Server(description = "Production Environment", url = "/")
        }
)
public class OpenApiConfig {

    static {
        // Prevents Swagger from trying to expand the RequestContext object in controller parameters
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
                                        .description("Enter JWT token. Example: `eyJhbGciOiJSUzI1NiJ9...`")
                        ));
    }
}