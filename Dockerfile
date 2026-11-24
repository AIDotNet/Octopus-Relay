# syntax=docker/dockerfile:1
# Single NativeAOT binary + minimal Alpine runtime (~26 MB total image).

FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
RUN apk add --no-cache clang build-base zlib-dev
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/ src/
RUN dotnet publish src/Octopus.Relay \
    -c Release \
    -p:PublishAot=true \
    -p:StripSymbols=true \
    -p:DebugType=None \
    -o /app

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine
WORKDIR /app
COPY --from=build /app/octopus-relay ./octopus-relay
RUN mkdir -p /data && chown $APP_UID:$APP_UID /data
ENV RELAY_DATA_DIR=/data
ENV RELAY_LISTEN=http://0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["./octopus-relay"]
