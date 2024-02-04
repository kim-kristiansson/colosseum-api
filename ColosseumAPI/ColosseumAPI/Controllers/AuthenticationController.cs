using ColosseumAPI.DTOs;
using ColosseumAPI.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace ColosseumAPI.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthenticationController(IApplicationUserService applicationUserService) :ControllerBase
    {
        private readonly IApplicationUserService _applicationUserService = applicationUserService;

        [HttpPost("google-signin")]
        public async Task<IActionResult> GoogleSignIn([FromForm] GoogleTokenDTO tokenDto)
        {
            if (string.IsNullOrWhiteSpace(tokenDto.Token)) {
                return BadRequest("Token is required.");
            }

            var payload = await _applicationUserService.VerifyGoogleTokenAsync(tokenDto.Token);
            if (payload == null) {
                return Unauthorized("Invalid or expired Google token.");
            }

            var user = await _applicationUserService.AuthenticateOrRegisterUser(payload);
            if (user == null) {
                return BadRequest("Failed to create or retrieve user.");
            }

            var userResponse = new UserResponseDTO {
                Id = user.Id,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Token = _applicationUserService.GenerateJwtToken(user)
            };

            return Ok(userResponse);
        }
    }
}