using Google.Apis.Auth;

namespace ColosseumAPI.Services.Interfaces
{
    public interface IGoogleTokenValidator
    {
        Task<GoogleJsonWebSignature.Payload?> ValidateAsync(string token, GoogleJsonWebSignature.ValidationSettings settings);
    }
}

