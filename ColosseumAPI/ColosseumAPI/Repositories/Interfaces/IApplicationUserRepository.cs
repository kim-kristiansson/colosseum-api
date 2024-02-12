using ColosseumAPI.Models;

namespace ColosseumAPI.Repositories.Interfaces
{
    public interface IApplicationUserRepository
    {
        Task AddAsync(ApplicationUser user);
        Task<ApplicationUser> GetByIdAsync(string appUserId);
        Task<ApplicationUser?> GetByEmailAsync(string email);
        Task<bool> SaveChangesAsync();
    }
}
