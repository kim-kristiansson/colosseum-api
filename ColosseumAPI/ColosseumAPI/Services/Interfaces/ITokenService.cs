using ColosseumAPI.Models;
using System.IdentityModel.Tokens.Jwt;

namespace ColosseumAPI.Services.Interfaces
{
    public interface ITokenService
    {
        TokenPayload IssueTokens(ApplicationUser appUser);
        public bool ValidateRefreshToken(string refreshToken);
        public string GetUserIdFromToken(string token);
    }
}
