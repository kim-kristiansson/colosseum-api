using ColosseumAPI.DTOs;
using ColosseumAPI.Repositories.Interfaces;
using ColosseumAPI.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace ColosseumAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController(IApplicationUserService applicationUserService, IApplicationUserRepository applicationUserRepository, ILogger<AuthenticationController> logger) :ControllerBase
    {
        private readonly IApplicationUserService _applicationUserService = applicationUserService;
        private readonly IApplicationUserRepository _applicationUserRepository = applicationUserRepository;
        private readonly ILogger<AuthenticationController> _logger = logger;

        [HttpPost("google-signin")]
        public async Task<IActionResult> GoogleSignIn([FromBody] GoogleTokenDTO tokenDto)
        {
            try {
                if (string.IsNullOrWhiteSpace(tokenDto.Token)) {
                    return BadRequest("Token is required.");
                }

                var appUserResponse = await _applicationUserService.GoogleSignInAsync(tokenDto.Token);
                return Ok(appUserResponse);
            }
            catch (ArgumentException ex) {
                return BadRequest(ex.Message);
            }
            catch (UnauthorizedAccessException ex) {
                return Unauthorized(ex.Message);
            }
            catch (InvalidOperationException ex) {
                return BadRequest(ex.Message);
            }
            catch (Exception ex) {
                _logger.LogError(ex, "An error occurred.");

                return StatusCode(500, "An error occurred. Please try again later.");
            }
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequestDTO refreshTokenRequest)
        {
            try {
                if (string.IsNullOrWhiteSpace(refreshTokenRequest.Token)) {
                    return BadRequest("Refresh token is required.");
                }

                var userResponse = await _applicationUserService.RefreshToken(refreshTokenRequest.Token);
                return Ok(userResponse);
            }
            catch (UnauthorizedAccessException ex) {
                return Unauthorized(ex.Message);
            }
            catch (Exception ex) {
                _logger.LogError(ex, "An error occurred.");

                return StatusCode(500, "An error occurred. Please try again later.");
            }
        }

    }
}