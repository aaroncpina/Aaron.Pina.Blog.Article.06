namespace Aaron.Pina.Blog.Article._06.Server;

public class TokenEntity
{
    public Guid     Id                    { get; init; } = Guid.NewGuid();
    public Guid     UserId                { get; init; }
    public DateTime CreatedAt             { get; init; }
    public string   RefreshToken          { get; set;  } = string.Empty;
    public DateTime RefreshTokenExpiresAt { get; set;  }
}
