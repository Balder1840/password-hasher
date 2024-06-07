# password-hasher
An [ASP.NET Core Identity password hasher](https://github.com/dotnet/aspnetcore/blob/main/src/Identity/Extensions.Core/src/PasswordHasher.cs) implemented in go.


# How to build

```cmd
go build -ldflags="-w -s" -o hasher.exe main.go
```

## for cross compile, e.g., build a linux binary on windows:
```cmd
set GOOS=linux
set GOARCH=arm
set CGO_ENABLED=0

go build -ldflags="-w -s" -o hasher_arm.exe main.go
```

# Usage
```cmd
hasher.exe your-password
```