using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ColosseumAPI.Services
{
    public class TokenService :ITokenService
    {
        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly string? _secretKey;

        public TokenService(IConfiguration configuration)
        {
            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
            _secretKey = configuration["JwtSettings:SecretKey"];

            if (string.IsNullOrEmpty(_issuer)) {
                throw new InvalidOperationException("JWT Issuer is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_audience)) {
                throw new InvalidOperationException("JWT Audience is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_secretKey)) {
                throw new InvalidOperationException("JWT Secret Key is not configured properly.");
            }
        }
        string ITokenService.GenerateJwtToken(ApplicationUser appUser)
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

        private string GenerateJwtToken(ApplicationUser appUser)
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
    }
}
