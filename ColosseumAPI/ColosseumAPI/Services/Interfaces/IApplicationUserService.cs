using ColosseumAPI.DTOs;
using ColosseumAPI.Models;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Mvc;

namespace ColosseumAPI.Services.Interfaces
{
    public interface IApplicationUserService
    {
        Task<ApplicationUser> AuthenticateOrRegisterUser(GoogleJsonWebSignature.Payload payload);
        Task<UserResponseDTO> GoogleSignInAsync(string googleToken);
        UserResponseDTO RefreshToken(ApplicationUser appUser);
        Task<bool> SaveChangesAsync();
        Task<GoogleJsonWebSignature.Payload?> VerifyGoogleTokenAsync(string token);
    }
}
