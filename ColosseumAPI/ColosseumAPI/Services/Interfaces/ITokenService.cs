using ColosseumAPI.Models;

namespace ColosseumAPI.Services.Interfaces
{
    public interface ITokenService
    {
        TokenPayload IssueTokens(ApplicationUser appUser);
    }
}
