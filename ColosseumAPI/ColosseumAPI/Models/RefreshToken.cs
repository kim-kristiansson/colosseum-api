namespace ColosseumAPI.Models
{
    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public required string Token {  get; set; }
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires {  get; set; }
    }
}
