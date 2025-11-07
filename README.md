# Yunus.JwtKit  
**JWT + Refresh Token + Cookie-based identity database library (for .NET)**
> Provided as a Plug-and-Play JWT with a focus on Clean Code
> NuGet: [https://www.nuget.org/packages/Yunus.JwtKit](https://www.nuget.org/packages/Yunus.JwtKit)

---

##  Purpose
I was tired of rewriting JWT services, interfaces, and cookie management over and over again in every project.
**Yunus.JwtKit** breaks this repetition by offering a secure, simple, and extensible framework without building a token system from scratch.

> Standard JWT solutions are typically only possible with *Access Token* generation.
> JwtKit, on the other hand, provides Refresh Token management, cookie-based registration support,
> and the immortality of ASP.NET Identity.

---

##  Features
-  Access & Refresh Token generation
-  Cookie or Header-based token transport
-  Secure cookie management protected against XSS/CSRF
-  Fully compatible with ASP.NET Identity (but not required)
-  Clean Code and Plug-and-Play installation
-  Native, Cross-Origin, Production support  

---

## SetUp

### 📦 NuGet
```bash
dotnet add package Yunus.JwtKit
```
## Documentation
- 🇹🇷 <a href="https://github.com/YunusDev/JwtKit/raw/main/docs/Yunus.JwtKit.pdf" download>Türkçe PDF Dokümanı (indir)</a>  
- 🇬🇧 <a href="https://github.com/YunusDev/JwtKit/raw/main/docs/Table%20of%20Contents.pdf" download>English PDF Documentation (download)</a>