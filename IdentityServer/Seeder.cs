using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer;

public class Seeder(IServiceProvider serviceProvider)
{
    private readonly IServiceProvider _serviceProvider = serviceProvider;

    public async Task AddScopes()
    {

        await using var scope = _serviceProvider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var apiScope = await manager.FindByNameAsync("api1");

        if (apiScope == null)
        {
            await manager.CreateAsync(new OpenIddictScopeDescriptor
            {
                DisplayName = "Api scope",
                Name = "api1",
                Resources =
                {
                "resource_server_1"
                }
            });
        }
    }

    public async Task AddClients()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var client = await manager.FindByClientIdAsync("web-client");

        if (client == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "web-client",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "Postman client application",
                RedirectUris =
            {
               new Uri("http://localhost:5000/swagger/oauth2-redirect.html")
            },
                PostLogoutRedirectUris =
            {
               new Uri("http://localhost:5000/resources")
            },
                Permissions =
            {
               Permissions.Endpoints.Authorization,
               Permissions.Endpoints.Logout,
               Permissions.Endpoints.Token,
               Permissions.GrantTypes.AuthorizationCode,
               Permissions.GrantTypes.RefreshToken,
               Permissions.ResponseTypes.Code,
               Permissions.Scopes.Email,
               Permissions.Scopes.Profile,
               Permissions.Scopes.Roles,
               Permissions.Prefixes.Scope + "api1"
            },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }
    }

    public async Task AddOidcDebuggerClient()
    {
        await using var scope = _serviceProvider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var client = await manager.FindByClientIdAsync("oidc-debugger");
        if (client == null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "oidc-debugger",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "Postman client application",
                RedirectUris =
            {
                new Uri("https://oidcdebugger.com/debug")
            },
                PostLogoutRedirectUris =
            {
                new Uri("https://oauth.pstmn.io/v1/callback")
            },
                Permissions =
            {
                Permissions.Endpoints.Authorization,
                Permissions.Endpoints.Logout,
                Permissions.Endpoints.Token,
                Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken,
                Permissions.ResponseTypes.Code,
                Permissions.Scopes.Email,
                Permissions.Scopes.Profile,
                Permissions.Scopes.Roles,
                Permissions.Prefixes.Scope + "api1"
            },
                //Requirements =
                //{
                //    Requirements.Features.ProofKeyForCodeExchange
                //}
            });
        }
    }
}
