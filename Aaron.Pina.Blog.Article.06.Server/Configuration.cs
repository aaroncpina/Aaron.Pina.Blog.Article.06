using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

namespace Aaron.Pina.Blog.Article._06.Server;

public static class Configuration
{
    public static class JwtBearer
    {
        public static Action<JwtBearerOptions> Options(RSA rsa) =>
            options =>
            {
                options.TokenValidationParameters = new()
                {
                    ClockSkew = TimeSpan.Zero,
                    ValidateIssuer = true,
                    ValidIssuer = "https://localhost",
                    ValidateAudience = true,
                    ValidAudience = "https://localhost",
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new RsaSecurityKey(rsa.ExportParameters(false))
                };
                options.MapInboundClaims = false;
            };
    }

    public static class Authorisation
    {
        public static void Options(AuthorizationOptions options)
        {
            options.AddPolicy("admin", policy =>
                policy.RequireAuthenticatedUser()
                      .RequireClaim("role", "admin"));
        }
    }
    
    public static class DbContext
    {
        public static void Options(DbContextOptionsBuilder builder) =>
            builder.UseSqlite("Data Source=tokens.db");
    }

    public static class RedisCache
    {
        public static void Options(RedisCacheOptions options)
        {
            options.Configuration = "localhost:6379";
            options.InstanceName = "redis-blacklist";
        }
    }
}
