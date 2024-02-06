using ColosseumAPI.Models;

namespace ColosseumAPI.DTOs
{
    public class UserResponseDTO
    {
        public string? Id { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? Token { get; set; }
        public RefreshToken? RefreshToken { get; set; }
    }
}
