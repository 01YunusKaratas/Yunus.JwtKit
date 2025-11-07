using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Yunus.JwtKit.Interface;

namespace Yunus.JwtKit.Service;

public class JwtService<TUser, TUserInfo> : IJwtTokenService<TUser, TUserInfo> where TUser : class, IHasRefreshToken where TUserInfo : class
{
    private readonly IConfiguration _configuration;
    private readonly UserManager<TUser> _userManager;
    private readonly ILogger<JwtService<TUser, TUserInfo>> _logger;

    public JwtService(UserManager<TUser> userManager,
     ILogger<JwtService<TUser, TUserInfo>> logger, IConfiguration configuration)
    {
        _configuration = configuration;
        _userManager = userManager;
        _logger = logger;
    }

    public async Task<string> GenerateAccessTokenAsync(TUser user, Func<TUser, IEnumerable<Claim>>? extraClaims = null)
    {
        try
        {
            //burda appsettingden çekiyor variablea atıyor
            var jwtSettings = _configuration.GetSection("JwtSettings");// kullan demek orayı
            var secretKey = jwtSettings["SecretKey"].Trim() ?? throw new InvalidOperationException("JWT SecretKey bulunamadı");
            var issuer = jwtSettings["Issuer"] ?? throw new InvalidOperationException("JWT Issuer bulunamadı");
            var audience = jwtSettings["Audience"] ?? throw new InvalidOperationException("JWT Audience bulunamadı");
            var expiryMinutes = int.Parse(jwtSettings["AccessTokenExpiryMinutes"] ?? "60");

            //Şifreleme anahtarını oluştur
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            Console.WriteLine($" GenerateToken - SecretKey: {secretKey}");
            Console.WriteLine($" GenerateToken - Issuer: {jwtSettings["Issuer"]}");
            Console.WriteLine($" GenerateToken - Audience: {jwtSettings["Audience"]}");


            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, GetUserId(user)),
                new(JwtRegisteredClaimNames.Sub, GetUserId(user)),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),//jwt ıd 
                new(JwtRegisteredClaimNames.Iat, DateTimeOffset.Now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)//token unique ıdentity card 
            };

            if (extraClaims != null)
            {

                claims.AddRange(extraClaims(user));
            }
            // Rolleri claims'e ekle
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }



            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(expiryMinutes),
                signingCredentials: credentials
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            // Debug için token'ı decode et
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(tokenString);
            var userIdClaim = jsonToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value;
            var subClaim = jsonToken.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Sub)?.Value;

            Console.WriteLine($" Token Generated - NameIdentifier: {userIdClaim}, Sub: {subClaim}");
            return tokenString;
        }
        catch (Exception ex)
        {
            _logger.LogError($"{ex.Message}", "Token oluşturma hatası");
            throw;
        }
    }

    //Random refresh token oluşturur
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    //Süresi dolmuş token'dan principal bilgilerini alır
    public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        try
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey bulunamadı");

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateLifetime = false // Süresi dolmuş token'ı da kabul et
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }

            return principal;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token principal alma hatası");
            throw;
        }
    }
    // Refresh token'ı validate eder
    public async Task<bool> ValidateRefreshTokenAsync(TUser user, string refreshToken)
    {
        try
        {
            return user.RefreshToken == refreshToken &&
                   user.RefreshTokenExpiryTime.HasValue &&
                   user.RefreshTokenExpiryTime.Value > DateTime.Now;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Refresh token validasyon hatası");
            return false;
        }
    }

    public async Task SaveRefreshTokenAsync(TUser user, string refreshToken)
    {
        try
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var refreshTokenExpiryDays = int.Parse(jwtSettings["RefreshTokenExpiryDays"] ?? "7");

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenExpiryDays);

            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Refresh token kaydedildi");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Refresh token kaydetme hatası");
            throw;
        }
    }

    public async Task RevokeRefreshTokenAsync(TUser user)
    {
        try
        {
            user.RefreshToken = null;
            user.RefreshTokenExpiryTime = null;
            await _userManager.UpdateAsync(user);

            _logger.LogInformation("Refresh token iptal edildi: ");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Refresh token iptal etme hatası");
            throw;
        }
    }

    public string GetUserIdFromToken(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadJwtToken(token);

            return jsonToken.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value ??
                   jsonToken.Claims.FirstOrDefault(x => x.Type == "sub")?.Value ??
                   string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token'dan user ID alma hatası");
            return string.Empty;
        }
    }

    public bool IsTokenValid(string token)
    {
        try
        {
            if (string.IsNullOrEmpty(token))
                return false;

            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey bulunamadı");
            var issuer = jwtSettings["Issuer"] ?? throw new InvalidOperationException("JWT Issuer bulunamadı");
            var audience = jwtSettings["Audience"] ?? throw new InvalidOperationException("JWT Audience bulunamadı");

            Console.WriteLine($"🔑 GenerateToken - SecretKey: {secretKey}");
            Console.WriteLine($"🔑 GenerateToken - Issuer: {jwtSettings["Issuer"]}");
            Console.WriteLine($"🔑 GenerateToken - Audience: {jwtSettings["Audience"]}");

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public string? GetTokenFromRequest(HttpRequest request)
    {
        try
        {
            // 1. Authorization Header'dan al (Bearer token)
            var authHeader = request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                return authHeader.Substring("Bearer ".Length).Trim();
            }

            // 2. Cookie'den al
            var cookieToken = GetTokenFromCookie(request, "AccessToken");
            if (!string.IsNullOrEmpty(cookieToken))
            {
                return cookieToken;
            }

            // 3. Query parameter'dan al (fallback)
            var queryToken = request.Query["token"].FirstOrDefault();
            if (!string.IsNullOrEmpty(queryToken))
            {
                return queryToken;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token alma hatası");
            return null;
        }
    }

    #region Cookie Operations

    //For Update 1.1.0
    //For local but changer for Front-end such as react cross platform porject.
    public bool CookieHttpOnly { get; set; } = false;
    public bool CookieSecure { get; set; } = false;
    public SameSiteMode CookieSameSite { get; set; } = SameSiteMode.Lax;

    

    public void SetAccessTokenCookie(HttpResponse response, string token, int expiryMinutes)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = CookieHttpOnly, //XSS korumasısssssssss
            Secure = CookieSecure,
            SameSite =CookieSameSite, // Strict değil, Lax!
            Expires = DateTime.Now.AddMinutes(expiryMinutes),
            Path = "/",
            IsEssential = true
        };

        response.Cookies.Append("AccessToken", token, cookieOptions);

        // Debug için
        Console.WriteLine($" AccessToken Cookie Set: {token.Substring(0, 20)}...");
        Console.WriteLine($" Cookie Options: HttpOnly={cookieOptions.HttpOnly}, Secure={cookieOptions.Secure}, SameSite={cookieOptions.SameSite}");

        _logger.LogInformation("Access token cookie set edildi");
    }

    public void SetRefreshTokenCookie(HttpResponse response, string refreshToken, int expiryDays)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = CookieHttpOnly,
            Secure = CookieSecure,
            SameSite = CookieSameSite,
            Expires = DateTime.Now.AddDays(expiryDays),
            Path = "/",
            IsEssential = true
        };

        response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);
        _logger.LogInformation("Refresh token cookie set edildi");
    }


    public string? GetTokenFromCookie(HttpRequest request, string cookieName)
    {
        return request.Cookies[cookieName];
    }

    public void ClearTokenCookies(HttpResponse response)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = CookieHttpOnly,
            Secure = CookieSecure,
            SameSite = CookieSameSite, // Strict değil, Lax!
            Expires = DateTime.Now.AddDays(-1), // Geçmişe tarih vererek sil
            Path = "/",
            IsEssential = true,

        };

        response.Cookies.Append("AccessToken", "", cookieOptions);
        response.Cookies.Append("RefreshToken", "", cookieOptions);

        _logger.LogInformation("Token cookie'leri temizlendi");
    }

    #endregion

    #region Helper Methods

    //JwtTokenResponse oluşturur
    public async Task<JwtTokenResponse<TUserInfo>> CreateTokenResponseAsync(TUser user, string accessToken, string refreshToken, Func<TUser, TUserInfo>? mapUser = null)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var expiryMinutes = int.Parse(jwtSettings["AccessTokenExpiryMinutes"] ?? "60");
        var roles = await _userManager.GetRolesAsync(user);
        var userInfo = mapUser != null ? mapUser(user) : Activator.CreateInstance<TUserInfo>();
        return new JwtTokenResponse<TUserInfo>
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            ExpiresIn = expiryMinutes * 60, // Saniye cinsinden
            IssuedAt = DateTime.Now,
            User = userInfo
        };
    }

    #endregion
    #region  Helper
    private string GetUserId(TUser user)
    {
        var idProperty = user?.GetType().GetProperty("Id");
        var idValue = idProperty?.GetValue(user)?.ToString();
        return !string.IsNullOrEmpty(idValue) ? idValue : Guid.NewGuid().ToString();
    }
    #endregion
}

