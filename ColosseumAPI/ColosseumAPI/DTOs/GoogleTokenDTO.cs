using System.ComponentModel.DataAnnotations;

namespace ColosseumAPI.DTOs
{
    public class GoogleTokenDTO
    {
        [Required]
        public string? Token { get; set; }
    }
}
