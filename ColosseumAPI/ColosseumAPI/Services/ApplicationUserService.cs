using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ColosseumAPI.Services
{
    public class ApplicationUserService :IApplicationUserService
    {
        private readonly IApplicationUserRepository _applicationUserRepository;
        private readonly ILogger<ApplicationUserService> _logger;
        private readonly string? _issuer;
        private readonly string? _audience;
        private readonly string? _secretKey;
        private readonly string? _googleClientId;

        public ApplicationUserService(IApplicationUserRepository applicationUserRepository,
                                 ILogger<ApplicationUserService> logger,
                                 IConfiguration configuration)
        {
            _applicationUserRepository = applicationUserRepository;
            _logger = logger;

            _issuer = configuration["JwtSettings:Issuer"];
            _audience = configuration["JwtSettings:Audience"];
            _secretKey = configuration["JwtSettings:SecretKey"];
            _googleClientId = configuration["GoogleAuthSettings:ClientId"];

            if (string.IsNullOrEmpty(_issuer)) {
                throw new InvalidOperationException("JWT Issuer is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_audience)) {
                throw new InvalidOperationException("JWT Audience is not configured properly in the settings.");
            }
            if (string.IsNullOrEmpty(_secretKey)) {
                throw new InvalidOperationException("JWT Secret Key is not configured properly.");
            }
            if (string.IsNullOrEmpty(_googleClientId)) {
                throw new InvalidOperationException("Google Client ID is not configured properly.");
            }
        }

        public async Task<ApplicationUser> AuthenticateOrRegisterUser(GoogleJsonWebSignature.Payload payload)
        {
            var user = await _applicationUserRepository.GetByEmailAsync(payload.Email);
            if (user == null) {
                user = new ApplicationUser {
                    Email = payload.Email
                };
                await _applicationUserRepository.AddAsync(user);
                await _applicationUserRepository.SaveChangesAsync();
            }
            return user;
        }

        public string GenerateJwtToken(ApplicationUser user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty)
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

        public IActionResult RefreshToken(ApplicationUser appUser)
        {
            if (appUser.RefreshToken == null) {
                return new UnauthorizedObjectResult("Invalid Refresh Token");
            }
            else if (appUser.RefreshToken.Expires < DateTime.Now) {
                return new UnauthorizedObjectResult("Refresh Token Expired");
            }

            string token = GenerateJwtToken(appUser);
            var newRefreshToken = GenerateRefreshToken();

            appUser.RefreshToken = newRefreshToken;

            return new OkObjectResult(token);
        }


        public Task<bool> SaveChangesAsync()
        {
            return _applicationUserRepository.SaveChangesAsync();
        }

        public async Task<GoogleJsonWebSignature.Payload?> VerifyGoogleTokenAsync(string token)
        {
            try {
                var settings = new GoogleJsonWebSignature.ValidationSettings { Audience = new List<string> { _googleClientId! } };
                return await GoogleJsonWebSignature.ValidateAsync(token, settings);
            }
            catch (InvalidJwtException ex) {
                _logger.LogError(ex, "Invalid JWT encountered while verifying Google token.");
                return null;
            }
            catch (Exception ex) {
                _logger.LogError(ex, "Error occurred while verifying Google token.");
                return null;
            }
        }
    }
}