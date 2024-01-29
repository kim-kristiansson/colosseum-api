using ColosseumAPI.Data;
using ColosseumAPI.Models;
using ColosseumAPI.Repositories.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace ColosseumAPI.Repositories
{
    public class ApplicationUserRepository(AppDbContext context) : IApplicationUserRepository
    {
        private readonly AppDbContext _context = context;

        public async Task AddAsync(ApplicationUser user)
        {
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
        }

        public async Task<ApplicationUser?> GetByEmailAsync(string email)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
        }

        public async Task<bool> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync() > 0;
        }
    }
}
