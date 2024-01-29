using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Google.Apis.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ColosseumAPI.Services
{
    public class ApplicationUserService(IApplicationUserRepository applicationUserRepository, ILogger<ApplicationUserService> logger, IConfiguration configuration) :IApplicationUserService
    {
        private readonly IApplicationUserRepository _applicationUserRepository = applicationUserRepository;
        private readonly ILogger<ApplicationUserService> _logger = logger;
        private readonly IConfiguration _configuration = configuration;

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
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Your_Secret_Key"));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty)
                // Additional claims
            };

            var token = new JwtSecurityToken(
                issuer: "your-issuer",
                audience: "your-audience",
                claims: claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public Task<bool> SaveChangesAsync()
        {
            return _applicationUserRepository.SaveChangesAsync();
        }

        public async Task<GoogleJsonWebSignature.Payload?> VerifyGoogleTokenAsync(string token)
        {
            try {
                var googleClientId = _configuration["GoogleAuthSettings:ClientId"];

                if (string.IsNullOrEmpty(googleClientId)) {
                    _logger.LogError("Google Client ID is not configured properly.");
                    return null;
                }

                var settings = new GoogleJsonWebSignature.ValidationSettings() {
                    Audience = new List<string>() { googleClientId }
                };

                var payload = await GoogleJsonWebSignature.ValidateAsync(token, settings);
                return payload;
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
