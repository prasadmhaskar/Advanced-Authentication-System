# =========================================
# STAGE 1: Build the Application
# =========================================
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Copy pom.xml and download dependencies (this layer will be cached)
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code
COPY src ./src

# Build the JAR (skipping tests to speed up deployment)
RUN mvn clean package -DskipTests

# =========================================
# STAGE 2: Run the Application
# =========================================
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Create a non-root user for security (Best Practice)
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copy the JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose the port
EXPOSE 8080

# Health Check for AWS App Runner
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -q --spider http://localhost:8080/actuator/health || exit 1

# Start the app
ENTRYPOINT ["java", "-jar", "app.jar"]