namespace Aaron.Pina.Blog.Article._06.Shared;

public record TokenResponse(string AccessToken, string RefreshToken, double AccessTokenExpiresIn);
