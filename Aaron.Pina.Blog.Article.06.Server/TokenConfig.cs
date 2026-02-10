namespace Aaron.Pina.Blog.Article._06.Server;

public class TokenConfig
{
    public double AccessTokenLifetime  { get; init; } = 10.0;      // ten minutes
    public double RefreshTokenLifetime { get; init; } = 262_980.0; // six months
}
