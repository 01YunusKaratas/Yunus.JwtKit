using System;

namespace Yunus.JwtKit.Interface;

   public interface IHasRefreshToken
    {
        string? RefreshToken { get; set; }
        DateTime? RefreshTokenExpiryTime { get; set; }
    }
