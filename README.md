# Yunus.JwtKit
Generic, extensible JWT & Refresh Token library for ASP.NET Core

Yunus.JwtKit is a generic library designed to simplify JWT (JSON Web Token) and refresh token generation, validation, and cookie management in ASP.NET Core projects.
Instead of writing separate services for different user types or response structures in each project, it provides complete flexibility by working with the TUser and TUserInfo types.

Features

Generic structure: Adaptable to any project with the TUser and TUserInfo types.

ASP.NET Identity integration: Works directly with the UserManager.

Refresh token support: Automatic generation, storage, validation, and revocation mechanism.

Cookie management: Securely creates and clears AccessToken and RefreshToken cookies.

Additional claims support: Custom claims can be added to the GenerateAccessTokenAsync method.

Modular usage: Add only the interfaces or services you need.
