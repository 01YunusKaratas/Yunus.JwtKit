using System;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
namespace Yunus.JwtKit.Interface;

public interface IJwtTokenService<TUser,TUserInfo>
{
    Task<string> GenerateAccessTokenAsync(TUser user,Func<TUser,IEnumerable<Claim>>? extraClaims =null);
    string GenerateRefreshToken();
    
    //Süresi dolmuş token'dan principal bilgilerini alır
    ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    

    // Refresh token'ı validate eder
    Task<bool> ValidateRefreshTokenAsync(TUser user, string refreshToken);
    


    // Kullanıcının refresh token'ını database'e kaydeder
    Task SaveRefreshTokenAsync(TUser user, string refreshToken);
    

    // Kullanıcının refresh token'ını iptal eder (logout)
    Task RevokeRefreshTokenAsync(TUser user);
    // Token'dan kullanıcı ID'sini alır
    string GetUserIdFromToken(string token);
    //Token'ın geçerli olup olmadığını kontrol eder
    bool IsTokenValid(string token);
    
    //HTTP Request'den token alır (Header veya Cookie'den)
    string? GetTokenFromRequest(HttpRequest request);
    
    // HTTP Cookie işlemleri
    

    // Access token'ı HTTP cookie'ye set eder
    void SetAccessTokenCookie(HttpResponse response, string token, int expiryMinutes);
    //Refresh token'ı HTTP cookie'ye set eder
    void SetRefreshTokenCookie(HttpResponse response, string refreshToken, int expiryDays);
    

    // HTTP cookie'den token alır
    string? GetTokenFromCookie(HttpRequest request, string cookieName);
    
    // Tüm token cookie'lerini temizler
    void ClearTokenCookies(HttpResponse response);


    // JwtTokenResponse oluşturur
    Task<JwtTokenResponse<TUserInfo>> CreateTokenResponseAsync(TUser user, string accessToken, string refreshToken, Func<TUser, TUserInfo>? mapUser = null);
}
public class JwtTokenResponse<TUserInfo>
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string TokenType { get; set; } = "Bearer";
    public int ExpiresIn { get; set; }
    public DateTime IssuedAt { get; set; } = DateTime.Now;
    public TUserInfo User { get; set; } = default!; // not request 
}


//Token response'da döndürülecek kullanıcı bilgileri

// public class UserInfo
// {
//     public string Id { get; set; } = string.Empty;
//     public string Email { get; set; } = string.Empty;
//     public string FullName { get; set; } = string.Empty;
//     public UserRole Role { get; set; }
//     public bool IsActive { get; set; }
// }
    
