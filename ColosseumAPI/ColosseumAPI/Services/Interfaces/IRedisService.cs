namespace ColosseumAPI.Services.Interfaces
{
    public interface IRedisService
    {
        public void InvalidateToken(string userId);
        public bool IsTokenValid(string userId, string jti);
        public void MarkTokenAsValid(string userId, string jti, DateTime expiration);
    }

}
