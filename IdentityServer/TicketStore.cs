using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer;

public static class TicketStoreExtensions
{
    public static void ConfigureAuthentication(this IServiceCollection services)
    {
        services.AddSingleton<ITicketStore, TicketStore>();
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();

        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<ITicketStore>((options, store) =>
            {
                options.LoginPath = "/Authenticate";
                options.Cookie.Name = "DreamTheater";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
                options.SlidingExpiration = true;
                options.SessionStore = store;
            });
    }
}

class AuthTicket
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string? Subject { get; set; }
    public byte[]? Value { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

class TicketStore : ITicketStore
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IDataProtector _protector;

    public TicketStore(IServiceProvider serviceProvider, IDataProtectionProvider dataProtectionProvider)
    {
        Console.WriteLine("TicketStore initialized.");
        _serviceProvider = serviceProvider;
        _protector = dataProtectionProvider.CreateProtector("Tickets");
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        using var dbContext = GetDbContext();

        var authTicket = new AuthTicket
        {
            Subject = ticket.Principal.GetClaim(Claims.Subject),
            Value = _protector.Protect(TicketSerializer.Default.Serialize(ticket)),
            ExpiresAt = ticket.Properties.ExpiresUtc ?? DateTimeOffset.UtcNow.AddHours(1)
        };

        dbContext.Tickets.Add(authTicket);
        await dbContext.SaveChangesAsync();

        return authTicket.Id;
    }

    public async Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        using var dbContext = GetDbContext();

        var authTicket = await dbContext.Tickets.SingleOrDefaultAsync(t => t.Id == key);
        if (authTicket != null)
        {
            authTicket.Value = _protector.Protect(TicketSerializer.Default.Serialize(ticket));
            authTicket.ExpiresAt = ticket.Properties.ExpiresUtc ?? DateTimeOffset.UtcNow.AddHours(1);
            await dbContext.SaveChangesAsync();
        }
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        using var dbContext = GetDbContext();

        var authTicket = await dbContext.Tickets.SingleOrDefaultAsync(t => t.Id == key);
        if (authTicket == null || authTicket.Value == null || authTicket.ExpiresAt < DateTimeOffset.UtcNow)
            return default;

        var decryptedTicket = _protector.Unprotect(authTicket.Value);
        return TicketSerializer.Default.Deserialize(decryptedTicket);
    }

    public async Task RemoveAsync(string key)
    {
        using var dbContext = GetDbContext();

        var authTicket = await dbContext.Tickets.SingleOrDefaultAsync(t => t.Id == key);
        if (authTicket != null)
        {
            dbContext.Tickets.Remove(authTicket);
            await dbContext.SaveChangesAsync();
        }
    }

    private ApplicationDbContext GetDbContext()
    {
        return _serviceProvider.CreateScope().ServiceProvider.GetRequiredService<ApplicationDbContext>();
    }
}