using Microsoft.AspNetCore.Authentication.JwtBearer;
using Aaron.Pina.Blog.Article._06.Shared;
using Aaron.Pina.Blog.Article._06.Server;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
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
