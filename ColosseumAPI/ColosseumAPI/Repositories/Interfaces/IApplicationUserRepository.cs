using ColosseumAPI.Models;

namespace ColosseumAPI.Repositories.Interfaces
{
    public interface IApplicationUserRepository
    {
        Task AddAsync(ApplicationUser user);
        Task<ApplicationUser?> GetByEmailAsync(string email);
        Task<ApplicationUser?> GetByRefreshTokenAsync(string refreshToken);
        Task<bool> SaveChangesAsync();
    }
}
