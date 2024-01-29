using ColosseumAPI.Models;
using Google.Apis.Auth;

namespace ColosseumAPI.Services.Interfaces
{
    public interface IApplicationUserService
    {
        Task<ApplicationUser> AuthenticateOrRegisterUser(GoogleJsonWebSignature.Payload payload);
        string GenerateJwtToken(ApplicationUser user);
        Task<bool> SaveChangesAsync();
        Task<GoogleJsonWebSignature.Payload?> VerifyGoogleTokenAsync(string token);
    }
}
