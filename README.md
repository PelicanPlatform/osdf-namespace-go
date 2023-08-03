# osdf-namespace
Go Gin app for managing osdf namespaces

## Quickstart: Tesing on localhost
### Prerequisites
- A CILogon OIDC Clinet ID and Secret
- Edit `OIDCClientID` and `OIDCClientSecret` in `main.go`

### Run Local Service
```
docker build -t namespace .
docker run -it -p 8080:8080 -v ${PWD}:/app/ namespace bash 
go run main.go
```