namespace Aaron.Pina.Blog.Article._06.Shared.Requests;

public record BlacklistRequest(Guid Jti, DateTime AccessTokenExpiresAt);
