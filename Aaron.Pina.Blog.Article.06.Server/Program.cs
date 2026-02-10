using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Distributed;
using Aaron.Pina.Blog.Article._06.Shared;
using Aaron.Pina.Blog.Article._06.Server;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using System.Security.Claims;

using var rsa = RSA.Create(2048);
var rsaKey = new RsaSecurityKey(rsa);

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStackExchangeRedisCache(Configuration.RedisCache.Options);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(Configuration.JwtBearer.Options(rsa));
builder.Services.AddAuthorization();
builder.Services.AddScoped<TokenRepository>();
builder.Services.AddDbContext<TokenDbContext>(Configuration.DbContext.Options);
builder.Services.Configure<TokenConfig>(builder.Configuration.GetSection(nameof(TokenConfig)));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<TokenDbContext>().Database.EnsureCreated();

app.MapGet("/register-user", () => Results.Ok(new UserResponse(Guid.NewGuid(), "user")))
   .AllowAnonymous();

app.MapGet("/register-admin", () => Results.Ok(new UserResponse(Guid.NewGuid(), "admin")))
   .AllowAnonymous();

app.MapPost("/token", (IOptionsSnapshot<TokenConfig> config, TokenRepository repository, UserRequest request) =>
    {
        var existing = repository.TryGetTokenByUserId(request.UserId);
        if (existing is not null)
        {
            return Results.BadRequest(new
            {
                Error = "User already has an active token",
                Message = "Use the /refresh endpoint with your refresh token to get a new token"
            });
        }
        var now = DateTime.UtcNow;
        var refreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(rsaKey, request.UserId, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(accessToken, refreshToken, config.Value.AccessTokenLifetime);
        repository.SaveToken(new TokenEntity
        {
            RefreshTokenExpiresAt = now.AddMinutes(config.Value.RefreshTokenLifetime),
            RefreshToken = refreshToken,
            UserId = request.UserId,
            CreatedAt = now
        });
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/refresh", (IOptionsSnapshot<TokenConfig> config, HttpContext context, TokenRepository repository) =>
    {
        var refreshToken = context.Request.Form["refresh_token"].FirstOrDefault();
        if (string.IsNullOrEmpty(refreshToken)) return Results.BadRequest();
        var existing = repository.TryGetTokenByRefreshToken(refreshToken);
        if (existing is null) return Results.BadRequest();
        if (existing.RefreshTokenExpiresAt < DateTime.UtcNow)
        {
            return Results.BadRequest(new
            {
                Error = "Refresh token has expired",
                Message = "Please login again to get a new token"
            });
        }
        var now = DateTime.UtcNow;
        var newRefreshToken = TokenGenerator.GenerateRefreshToken();
        var accessToken = TokenGenerator.GenerateToken(rsaKey, existing.UserId, now, config.Value.AccessTokenLifetime);
        var response = new TokenResponse(accessToken, newRefreshToken, config.Value.AccessTokenLifetime);
        existing.RefreshTokenExpiresAt = now.AddMinutes(config.Value.RefreshTokenLifetime);
        existing.RefreshToken = newRefreshToken;
        repository.UpdateToken(existing);
        return Results.Ok(response);
    })
   .AllowAnonymous();

app.MapPost("/blacklist", async (IDistributedCache blacklist, BlacklistRequest request) =>
    {
        var expires = new DateTimeOffset(request.AccessTokenExpiresAt);
        if (expires < DateTimeOffset.UtcNow) return Results.BadRequest("Token already expired");
        await blacklist.SetStringAsync(request.Jti.ToString(), string.Empty, new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = expires
        });
        return Results.Ok();
    })
   .RequireAuthorization("admin");

app.MapGet("/user", (HttpContext context) =>
    {
        var role = context.User.FindFirstValue("role");
        if (role is null) return Results.Unauthorized();
        var sub = context.User.FindFirstValue("sub");
        var parsed = Guid.TryParse(sub, out var userId); 
        if (!parsed) return Results.Unauthorized();
        return Results.Ok(new UserResponse(userId, role));
    })
   .RequireAuthorization();

app.Run();
