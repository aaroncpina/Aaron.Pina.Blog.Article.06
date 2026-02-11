namespace Aaron.Pina.Blog.Article._06.Shared.Responses;

public record TokenResponse(string AccessToken, string RefreshToken, double AccessTokenExpiresIn);
