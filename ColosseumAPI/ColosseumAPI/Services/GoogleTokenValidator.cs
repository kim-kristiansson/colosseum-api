using ColosseumAPI.Services.Interfaces;
using Google.Apis.Auth;

namespace ColosseumAPI.Services
{
    public class GoogleTokenValidator : IGoogleTokenValidator
    {
        public async Task<GoogleJsonWebSignature.Payload?> ValidateAsync(string token, GoogleJsonWebSignature.ValidationSettings settings)
        {
            return await GoogleJsonWebSignature.ValidateAsync(token, settings);
        }
    }
}
