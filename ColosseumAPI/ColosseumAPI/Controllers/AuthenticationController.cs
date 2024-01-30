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
        public async Task<IActionResult> GoogleSignIn([FromBody] GoogleTokenDTO tokenDto)
        {
            if (string.IsNullOrWhiteSpace(tokenDto.Token)) {
                return BadRequest("Token is required.");
            }

            var payload = await _applicationUserService.VerifyGoogleTokenAsync(tokenDto.Token);

            if (payload == null) {
                // Respond with an appropriate error message or status code
                return Unauthorized("Invalid or expired Google token.");
            }

            var user = await _applicationUserService.AuthenticateOrRegisterUser(payload);
            if (user == null) {
                // Handle the case where user creation or lookup failed
                return BadRequest("Failed to create or retrieve user.");
            }

            var jwtToken = _applicationUserService.GenerateJwtToken(user);
            return Ok(new { Token = jwtToken });
        }
    }
}