# ---- Build stage ----
FROM gradle:8.5-jdk17 AS build
WORKDIR /app
COPY settings.gradle.kts build.gradle.kts ./
COPY src ./src
RUN gradle --no-daemon bootJar

# ---- Runtime stage ----
FROM eclipse-temurin:17-jre
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /app/data && \
    echo "TOP-SECRET: flag{kotlin_path_traversal_works}" > /app/secret.txt && \
    echo "public sample" > /app/data/sample.txt
COPY --from=build /app/build/libs/vuln-kotlin-web.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
