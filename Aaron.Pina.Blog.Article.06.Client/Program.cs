using Aaron.Pina.Blog.Article._06.Shared.Responses;
using Aaron.Pina.Blog.Article._06.Client;
using Aaron.Pina.Blog.Article._06.Shared;
using System.Net.Http.Headers;

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

app.MapGet("{role}/login", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    var client = factory.CreateClient($"{role}-server-api");
    using var registerResponse = await client.GetAsync("/register");
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

app.MapGet("{role}/info", async (IHttpClientFactory factory, TokenRepository repository, string role) =>
{
    if (!Roles.ValidRoles.Contains(role)) return Results.BadRequest("Invalid role");
    var client = factory.CreateClient($"{role}-server-api");
    if (client.BaseAddress is null) return Results.BadRequest("Unable to get base address");
    var uriBuilder = new UriBuilder(client.BaseAddress) { Path = "user" };
    using var request = new HttpRequestMessage(HttpMethod.Get, uriBuilder.Uri);
    var store = repository.TokenStores[role];
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", store.AccessToken);
    using var response = await client.SendAsync(request);
    if (!response.IsSuccessStatusCode) return Results.BadRequest("Unable to get user info");
    var user = await response.Content.ReadFromJsonAsync<UserResponse>();
    if (user is null) return Results.BadRequest("Unable to parse user info");
    return Results.Ok($"User Id: {user.UserId}");
});

app.Run();
