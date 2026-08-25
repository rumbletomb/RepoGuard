FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/RepoGuard.Api/RepoGuard.Api.csproj -c Release -o /app --no-self-contained
FROM mcr.microsoft.com/dotnet/aspnet:10.0
RUN adduser --disabled-password --gecos "" --uid 10001 repoguard
WORKDIR /app
COPY --from=build /app .
RUN mkdir /data && chown repoguard:repoguard /data
USER repoguard
ENV ASPNETCORE_URLS=http://+:8080 REPOGUARD_DATA=/data/repoguard.json
EXPOSE 8080
ENTRYPOINT ["dotnet","RepoGuard.Api.dll"]
