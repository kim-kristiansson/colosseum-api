namespace ColosseumAPI.Models
{
    public class TokenPayload
    {
        public required string? AccessToken { get; set; }
        public required string? RefreshToken { get; set; }

    }
}
