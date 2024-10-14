using System.Diagnostics;
using IdentityServer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<DbContext>(options =>
{
    options.UseSqlite("Data Source=Identity.sqlite3");
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<DbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("connect/authorize")
            .SetLogoutEndpointUris("connect/logout")
            .SetTokenEndpointUris("connect/token")
            .SetUserinfoEndpointUris("connect/userinfo");

        options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow();
        // .RequireProofKeyForCodeExchange();

        options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

        options
            .AddDevelopmentEncryptionCertificate()
            .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableLogoutEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .DisableTransportSecurityRequirement();
    });

builder.Services.AddTransient<AuthorizationService>();
builder.Services.AddControllers();
builder.Services.AddRazorPages();
builder.Services.AddTransient<Seeder>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.WebHost.UseUrls(["http://localhost:8080"]);
// builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo("."));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(c =>
{
    c.LoginPath = "/Authenticate";
    c.Cookie.Name = "Brownie";
    c.SlidingExpiration = true;
    c.SessionStore = null;
});


var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<Seeder>();
    await seeder.AddClients();
    await seeder.AddScopes();
    await seeder.AddOidcDebuggerClient();

    var tokenManager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
    var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

    await tokenManager.PruneAsync(DateTime.UtcNow);
    await authorizationManager.PruneAsync(DateTime.UtcNow);
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(b => b.AllowAnyHeader().AllowAnyMethod().WithOrigins("http://localhost:5000"));
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapRazorPages();
app.Run();
