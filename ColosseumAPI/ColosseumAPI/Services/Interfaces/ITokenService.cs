using ColosseumAPI.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ColosseumAPI.Services.Interfaces
{
    public interface ITokenService
    {
        string GenerateJwtToken(ApplicationUser user);
        RefreshToken GenerateRefreshToken();
    }
}
