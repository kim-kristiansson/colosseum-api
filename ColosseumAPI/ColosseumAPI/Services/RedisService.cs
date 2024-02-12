using ColosseumAPI.Services.Interfaces;
using StackExchange.Redis;

namespace ColosseumAPI.Services
{
    public class RedisService(ConnectionMultiplexer redis) :IRedisService
    {
        private readonly IDatabase _db = redis.GetDatabase();

        public bool IsTokenValid(string userId, string jti)
        {
            var key = $"valid_refresh_tokens:{userId}";
            var validJti = _db.StringGet(key);
            return validJti == jti;
        }

        public void MarkTokenAsValid(string userId, string jti, DateTime expiration)
        {
            var key = $"valid_refresh_tokens:{userId}";
            var value = jti;
            _db.StringSet(key, value, expiration - DateTime.UtcNow);
        }

        public void InvalidateToken(string userId)
        {
            var key = $"valid_refresh_tokens:{userId}";
            _db.KeyDelete(key);
        }

    }

}
