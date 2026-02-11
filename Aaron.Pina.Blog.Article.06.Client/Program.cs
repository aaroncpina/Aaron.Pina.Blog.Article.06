using Aaron.Pina.Blog.Article._06.Shared.Responses;
using Aaron.Pina.Blog.Article._06.Shared.Requests;
using static System.Net.Mime.MediaTypeNames;
using Aaron.Pina.Blog.Article._06.Client;
using Aaron.Pina.Blog.Article._06.Shared;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<TokenRepository>();
builder.Services.AddHostedService<TokenRefresherService>();
builder.Services.AddTransient(Configuration.TokenServer.TokenRefreshHandlerFactory);

foreach (var role in Roles.ValidRoles)
{
    builder.Services.AddHttpClient($"{role}-server-api", Configuration.TokenServer.HttpClientSettings)
                    .ConfigurePrimaryHttpMessageHandler(Configuration.TokenServer.HttpMessageHandlerSettings)
                    .AddHttpMessageHandler(Configuration.TokenServer.HttpMessageHandlerFor(role));
}

var app = builder.Build();

app.MapGet("/{role}/login", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    using var client = factory.CreateClient($"{role}-server-api");
    using var registerResponse = await client.GetAsync($"{role}/register");
    if (!registerResponse.IsSuccessStatusCode) return Results.BadRequest("Unable to register");
    var userId = await registerResponse.Content.ReadFromJsonAsync<Guid>();
    if (userId == Guid.Empty) return Results.BadRequest("Unable to parse user id");
    using var tokenResponse = await client.GetAsync($"/token?userId={userId}");
    if (!tokenResponse.IsSuccessStatusCode) return Results.BadRequest("Unable to get token");
    var token = await tokenResponse.Content.ReadFromJsonAsync<TokenResponse>();
    if (token is null) return Results.BadRequest("Unable to parse token");
    var store = repository.TokenStores[role];
    store.AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(token.AccessTokenExpiresIn);
    store.RefreshToken = token.RefreshToken;
    store.AccessToken = token.AccessToken;
    return Results.Ok("Logged in");
});

app.MapGet("/{role}/info", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    using var client = factory.CreateClient($"{role}-server-api");
    if (client.BaseAddress is null) return Results.BadRequest("Unable to get base address");
    var uriBuilder = new UriBuilder(client.BaseAddress) { Path = "user" };
    using var request = new HttpRequestMessage(HttpMethod.Get, uriBuilder.Uri);
    var store = repository.TokenStores[role];
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", store.AccessToken);
    using var response = await client.SendAsync(request);
    if (!response.IsSuccessStatusCode) return Results.BadRequest("Unable to get user info");
    var user = await response.Content.ReadFromJsonAsync<UserResponse>();
    if (user is null) return Results.BadRequest("Unable to parse user info");
    return Results.Ok($"User Id: {user.UserId} | Role: {user.Role}");
});

app.MapGet("/admin/blacklist", async (IHttpClientFactory factory, TokenRepository repository) =>
{
    var userStore = repository.TokenStores["user"];
    if (userStore.AccessTokenExpiresAt is null) return Results.BadRequest("User token not yet initialised");
    var handler = new JwtSecurityTokenHandler();
    if (!handler.CanReadToken(userStore.AccessToken)) return Results.BadRequest("Invalid access token");
    var token = handler.ReadJwtToken(userStore.AccessToken);
    var claim = token.Claims.FirstOrDefault(c => c.Type == "jti");
    if (claim is null || !Guid.TryParse(claim.Value, out var jti)) return Results.BadRequest("No jti claim found");
    var expiresIn = userStore.AccessTokenExpiresAt.Value.Subtract(DateTime.UtcNow);
    using var client = factory.CreateClient("admin-server-api");
    if (client.BaseAddress is null) return Results.BadRequest("Unable to get base address");
    var uriBuilder = new UriBuilder(client.BaseAddress) { Path = "blacklist" };
    var adminStore = repository.TokenStores["admin"];
    using var request = new HttpRequestMessage(HttpMethod.Post, uriBuilder.Uri);
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminStore.AccessToken);
    var json = JsonSerializer.Serialize(new BlacklistRequest(jti, expiresIn.TotalSeconds));
    request.Content = new StringContent(json, Encoding.UTF8, Application.Json);
    var response = await client.SendAsync(request);
    if (!response.IsSuccessStatusCode) return Results.BadRequest("Unable to blacklist token");
    return Results.Ok("Token blacklisted");
});

app.Run();
