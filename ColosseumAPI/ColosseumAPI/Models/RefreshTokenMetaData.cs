namespace ColosseumAPI.Models
{
    public class RefreshTokenMetaData
    {
        public Guid UserId { get; set; }
        public required string TokenHash {  get; set; }
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires {  get; set; }
    }
}
