using ColosseumAPI.DTOs;
using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services;
using ColosseumAPI.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace ColosseumAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController(IApplicationUserService applicationUserService, IApplicationUserRepository applicationUserRepository) :ControllerBase
    {
        private readonly IApplicationUserService _applicationUserService = applicationUserService;
        private readonly IApplicationUserRepository _applicationUserRepository = applicationUserRepository;

        [HttpPost("google-signin")]
        public async Task<IActionResult> GoogleSignIn([FromBody] GoogleTokenDTO tokenDto)
        {
            if (string.IsNullOrWhiteSpace(tokenDto.Token)) {
                return BadRequest("Token is required.");
            }

            var payload = await _applicationUserService.VerifyGoogleTokenAsync(tokenDto.Token);
            if (payload == null) {
                return Unauthorized("Invalid or expired Google token.");
            }

            var appUser = await _applicationUserService.AuthenticateOrRegisterUser(payload);
            if (appUser == null) {
                return BadRequest("Failed to create or retrieve user.");
            }

            var refreshToken = _applicationUserService.GenerateRefreshToken();

            var appUserResponse = new UserResponseDTO {
                Id = appUser.Id,
                FirstName = appUser.FirstName,
                LastName = appUser.LastName,
                Email = appUser.Email,
                Token = _applicationUserService.GenerateJwtToken(appUser),
                RefreshToken = refreshToken
            };


            return Ok(appUserResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO refreshTokenRequest)
        {
            if (string.IsNullOrEmpty(refreshTokenRequest.Token))
            {
                return BadRequest("Refresh token is required.");
            }

            var appUser = await _applicationUserRepository.GetByRefreshTokenAsync(refreshTokenRequest.Token);

            if (appUser == null) {
                return Unauthorized("User not found or invalid refresh token.");
            }

            return _applicationUserService.RefreshToken(appUser);
        }
    }
}