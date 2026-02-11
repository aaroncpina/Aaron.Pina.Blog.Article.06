using Aaron.Pina.Blog.Article._06.Shared;

namespace Aaron.Pina.Blog.Article._06.Client;

public class TokenRepository
{
    public Dictionary<string, TokenStore> TokenStores { get; } =
        Roles.ValidRoles.ToDictionary(r => r, _ => new TokenStore());
}
