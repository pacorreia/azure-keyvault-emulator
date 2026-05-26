FROM golang:1.24 AS build
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} -w -s" -o /out/azure-keyvault-emulator .

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --from=build /out/azure-keyvault-emulator /usr/local/bin/azure-keyvault-emulator
EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/azure-keyvault-emulator"]
