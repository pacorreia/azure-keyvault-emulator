FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN go build -o /out/azure-keyvault-emulator .

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /out/azure-keyvault-emulator /usr/local/bin/azure-keyvault-emulator
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/azure-keyvault-emulator"]
