# Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY InfraAdvisor.csproj .
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app --no-restore

# Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_ENVIRONMENT=Production
# Render inyecta PORT (por defecto 10000); la app escucha en 0.0.0.0:$PORT
EXPOSE 10000
ENTRYPOINT ["dotnet", "InfraAdvisor.dll"]
