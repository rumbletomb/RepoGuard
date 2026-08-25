FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/RepoGuard.Api/RepoGuard.Api.csproj -c Release -o /app --no-self-contained
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
ARG TRIVY_VERSION=0.58.1
ARG GITLEAKS_VERSION=8.23.3
ARG SYFT_VERSION=1.18.1
ARG GRYPE_VERSION=0.85.0
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv \
    && python3 -m venv /opt/security-tools \
    && /opt/security-tools/bin/pip install --no-cache-dir semgrep==1.99.0 checkov==3.2.340 \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks \
    && curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin syft \
    && curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" | tar -xz -C /usr/local/bin grype \
    && ln -s /opt/security-tools/bin/semgrep /usr/local/bin/semgrep \
    && ln -s /opt/security-tools/bin/checkov /usr/local/bin/checkov \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
RUN mkdir /data && chown $APP_UID:$APP_UID /data
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080 REPOGUARD_DATA=/data/repoguard.json REPOGUARD_ARTIFACTS=/data/artifacts \
    PATH="/opt/security-tools/bin:${PATH}" SEMGREP_SEND_METRICS=off HOME=/data TRIVY_CACHE_DIR=/data/cache/trivy GRYPE_DB_CACHE_DIR=/data/cache/grype
EXPOSE 8080
ENTRYPOINT ["dotnet","RepoGuard.Api.dll"]
