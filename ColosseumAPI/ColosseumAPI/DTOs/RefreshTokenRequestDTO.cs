using System.ComponentModel.DataAnnotations;

namespace ColosseumAPI.DTOs
{
    public class RefreshTokenRequestDTO
    {
        [Required]
        public string? Token {  get; set; }
    }
}
