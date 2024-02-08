using ColosseumAPI.DTOs;
using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Google.Apis.Auth;
namespace ColosseumAPI.Services
{
    public class ApplicationUserService :IApplicationUserService
    {
        private readonly IApplicationUserRepository _applicationUserRepository;
        private readonly ILogger<ApplicationUserService> _logger;
        private readonly ITokenService _tokenService;

        private readonly string? _googleClientId;

        public ApplicationUserService(IApplicationUserRepository applicationUserRepository,
                                 ILogger<ApplicationUserService> logger,
                                 IConfiguration configuration, 
                                 ITokenService tokenService)
        {
            _applicationUserRepository = applicationUserRepository;
            _logger = logger;
            _tokenService = tokenService;

            _googleClientId = configuration["GoogleAuthSettings:ClientId"];

            if (string.IsNullOrEmpty(_googleClientId)) {
                _logger.LogError("Google Client ID is not configured properly.");
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

        public async Task<UserResponseDTO> GoogleSignInAsync(string googleToken)
        {
            if (string.IsNullOrWhiteSpace(googleToken)) {
                throw new ArgumentException("Google token is required.", nameof(googleToken));
            }

            var payload = await VerifyGoogleTokenAsync(googleToken);

            if (payload == null) {
                throw new UnauthorizedAccessException("Invalid or expired Google token.");
            }

            var appUser = await AuthenticateOrRegisterUser(payload);

            if (appUser == null) {
                throw new InvalidOperationException("Failed to create or retrieve user.");
            }

            var tokenPayload = _tokenService.IssueTokens(appUser);

            return new UserResponseDTO {
                Id = appUser.Id,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName,
                Email = appUser.Email,
                AccessToken = tokenPayload.AccessToken,
                RefreshToken = tokenPayload.RefreshToken.
            };
        }

        public UserResponseDTO RefreshToken(ApplicationUser appUser, string presentedRefreshToken)
        {
            var hashedPresentedToken = _tokenService.HashRefreshToken(presentedRefreshToken);

            if (appUser.RefreshTokenMetaData?.TokenHash == null || appUser.RefreshTokenMetaData?.TokenHash != hashedPresentedToken) {
                throw new UnauthorizedAccessException("Invalid Refresh Token");
            }

            string token = _tokenService.GenerateJwtToken(appUser);
            var newRefreshToken = _tokenService.GenerateRefreshToken();

            appUser.RefreshTokenHash = _tokenService.HashRefreshToken(newRefreshToken.Token);

            _applicationUserRepository.SaveChangesAsync();
            // Save changes to the ApplicationUser
            // _applicationUserRepository.Update(appUser);
            // await _applicationUserRepository.SaveChangesAsync();

            return new UserResponseDTO {
                Id = appUser.Id,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName,
                Email = appUser.Email,
                AccessToken = token,
                RefreshToken = newRefreshToken.Token
            };
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
            }
            catch (HttpRequestException ex) {
                _logger.LogError(ex, "Network error occurred while verifying Google token.");
            }
            catch (Exception ex) {
                _logger.LogError(ex, "Unexpected error occurred while verifying Google token.");
            }
            return null;
        }
    }
}