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

        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly string? _secretKey;

        public TokenService(IConfiguration configuration, ILogger<ApplicationUserService> logger)
        {
            _logger = logger;

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

        public string GenerateJwtToken(ApplicationUser appUser)
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

        public RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7)
            };

            return refreshToken;
        }
    }
}
