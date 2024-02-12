using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ColosseumAPI.Services
{
    public class TokenService :ITokenService
    {
        private readonly ILogger _logger;
        private readonly IRedisService _redisService;

        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly string? _secretKey;

        public TokenService(IConfiguration configuration, ILogger<ApplicationUserService> logger, IRedisService redisService)
        {
            _logger = logger;
            _redisService = redisService;

            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
            _secretKey = configuration["JwtSettings:SecretKey"];

            if (string.IsNullOrEmpty(_issuer)) {
                _logger.LogError("JWT Issuer is not configured properly in the settings.");
                throw new InvalidOperationException("JWT Issuer is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_audience)) {
                _logger.LogError("JWT Audience is not configured properly in the settings.");
                throw new InvalidOperationException("JWT Audience is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_secretKey)) {
                _logger.LogError("JWT Secret Key is not configured properly.");
                throw new InvalidOperationException("JWT Secret Key is not configured properly.");
            }
        }

        public bool ValidateRefreshToken(string refreshToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey!)),
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateLifetime = true, 
                ClockSkew = TimeSpan.Zero 
            };

            try {
                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(refreshToken, validationParameters, out validatedToken);

                // Extract user ID from token claims
                var userIdClaim = principal.FindFirst(ClaimTypes.NameIdentifier) ?? principal.FindFirst(JwtRegisteredClaimNames.Sub);
                if (userIdClaim == null || string.IsNullOrWhiteSpace(userIdClaim.Value)) {
                    return false; 
                }

                var jtiClaim = principal.FindFirst(JwtRegisteredClaimNames.Jti);
                if (jtiClaim == null || string.IsNullOrWhiteSpace(jtiClaim.Value)) {
                    return false; 
                }

                // Check if the token JTI is the latest valid token for the user
                if (!_redisService.IsTokenValid(userIdClaim.Value, jtiClaim.Value)) {
                    return false; // Token has been rotated or is otherwise invalid
                }

                // Token is valid
                return true;
            }
            catch {
                // Token validation failed
                return false;
            }
        }

        string GenerateAccessToken(ApplicationUser appUser)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, appUser.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, appUser.Email ?? string.Empty)
                // Additional claims
            };

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        string GenerateRefreshToken(ApplicationUser appUser)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, appUser.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, jti), // Add the JTI claim
            };

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: credentials);

            var refreshToken = new JwtSecurityTokenHandler().WriteToken(token);

            _redisService.MarkTokenAsValid(appUser.Id, jti, token.ValidTo);

            return refreshToken;
        }

        public string GetUserIdFromToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);

            var userIdClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == JwtRegisteredClaimNames.Sub);

            if (userIdClaim == null) {
                throw new InvalidOperationException("Invalid token: user ID claim not found.");
            }

            return userIdClaim.Value;
        }


        string HashRefreshToken(string token)
        {
            var hashedBytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
            return BitConverter.ToString(hashedBytes).Replace("-", "").ToLowerInvariant();
        }

        public TokenPayload IssueTokens(ApplicationUser appUser)
        {
            return new TokenPayload {
                AccessToken = GenerateAccessToken(appUser),
                RefreshToken = GenerateRefreshToken(appUser)
            };
        }
    }
}
