# Advanced Authentication System
Enterprise-grade authentication system built with Spring Boot 3, JDK 17, and PostgreSQL.
Supports JWT, Email Verification, OTP-based login, Role-based access, and Secure Password Hashing.

* Features
-User Registration (with validation)
-Login using JWT
-Email Verification Flow
-Forgot Password + Reset Password
-OTP-based Authentication
-Role-based Access Control
-Secure Password Hashing (BCrypt)
-PostgreSQL Integration
-Environment Variable–based Credentials
-Logging + Exception Handling

* Tech Stack
-Java 17
-Spring Boot 3.3
-Spring Security 6
-PostgreSQL 16
-Maven
-JWT
-Lombok

* Project Structure
src/main/java/com/pnm/auth/
    controller/
    service/
    repository/
    entity/
    dto/
    config/
    security/
    exceptions/
src/main/resources/
    application.properties
    application-secret.properties (gitignored)

* Running the Project
-Set environment variables
DB_URL=jdbc:postgresql://localhost:5432/project1_auth
DB_USERNAME=postgres
DB_PASSWORD=yourpassword
EMAIL_API_KEY=xxxxx

* Run with Maven
mvn spring-boot:run

* API Testing
Use Postman collection

*License
This project is for learning.
