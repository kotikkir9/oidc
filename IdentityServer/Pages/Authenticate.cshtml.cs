using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Pages;

public class AuthenticateModel(ILogger<AuthenticateModel> logger) : PageModel
{
    private readonly ILogger _logger = logger;

    [BindProperty]
    public string? ReturnUrl { get; set; }
    public string Email { get; set; } = Constants.Email;
    public string Password { get; set; } = Constants.Password;
    public string AuthStatus { get; set; } = string.Empty;

    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        return Page();
    }

    public async Task<IActionResult> OnPostAsync(string email, string password)
    {
        _logger.LogInformation("POST authenticate page called");

        if (email != Constants.Email || password != Constants.Password)
        {
            AuthStatus = "Email or password is invalid";
            return Page();
        }

        List<Claim> claims = [new(Claims.Subject, Constants.Subject)];

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

        if (!string.IsNullOrEmpty(ReturnUrl))
        {
            return Redirect(ReturnUrl);
        }

        AuthStatus = "Successfully authenticated";

        return Page();
    }
}
