namespace Aaron.Pina.Blog.Article._06.Client;

public static class Configuration
{
    public static class TokenServer
    {
        public static void HttpClientSettings(HttpClient client)
        {
            client.BaseAddress = new Uri("https://localhost:5001");
            client.Timeout = TimeSpan.FromSeconds(10);
        }

        public static HttpMessageHandler HttpMessageHandlerSettings() =>
            new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

        public static Func<IServiceProvider, DelegatingHandler> HttpMessageHandlerFor(string role) =>
            provider =>
            {
                var factory = provider.GetRequiredService<Func<string, TokenRefreshHandler>>();
                return factory(role);
            };

        public static Func<string, TokenRefreshHandler> TokenRefreshHandlerFactory(IServiceProvider provider) =>
            role =>
            {
                var repository = provider.GetRequiredService<TokenRepository>();
                return new TokenRefreshHandler(repository.TokenStores[role]);
            };
    }
}
