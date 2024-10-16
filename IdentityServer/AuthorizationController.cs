using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer;

[ApiController]
public class AuthorizationController(IOpenIddictApplicationManager applicationManager, IOpenIddictScopeManager scopeManager, AuthorizationService authService) : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager = applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager = scopeManager;
    private readonly AuthorizationService _authService = authService;

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    public async Task<IActionResult> Authorize()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var parameters = _authService.ParseOAuthParameters(HttpContext, [Parameters.Prompt]);

        if (request.HasPrompt(Prompts.Login))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                });
        }

        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!_authService.IsAuthenticated(result, request))
        {
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                });
        }

        // var application =
        //     await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
        //     throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // if (await _applicationManager.GetConsentTypeAsync(application) != ConsentTypes.Implicit)
        // {
        //     return Forbid(
        //         authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        //         properties: new AuthenticationProperties(new Dictionary<string, string?>
        //         {
        //             [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidClient,
        //             [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Only implicit consent clients are supported"
        //         }));
        // }

        // var consentClaim = result.Principal!.GetClaim(Constants.ConsentNaming);

        // it might be extended in a way that consent claim will contain list of allowed client ids.
        // if (consentClaim != Constants.GrantAccessValue || request.HasPrompt(Prompts.Consent))
        // {
        //     await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        //     var returnUrl = HttpUtility.UrlEncode(_authService.BuildRedirectUrl(HttpContext.Request, parameters));
        //     var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

        //     return Redirect(consentRedirectUrl);
        // }

        var userId = result.Principal!.FindFirst(Claims.Subject)?.Value;

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, Constants.Email)
            .SetClaim(Claims.Name, Constants.Name)
            .SetClaims(Claims.Role, ["root", "admin"]);

        var scopes = request.GetScopes();
        identity.SetScopes(scopes);

        var resources = await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync();
        identity.SetResources(resources);

        // identity.SetDestinations(e => AuthorizationService.GetDestinations(identity, e));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("The specified grant type is not supported.");

        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var userId = result.Principal!.GetClaim(Claims.Subject);

        if (string.IsNullOrEmpty(userId))
        {
            return Forbid(
               authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
               properties: new AuthenticationProperties(new Dictionary<string, string?>
               {
                   [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                   [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Cannot find user from the token."
               }));
        }

        var identity = new ClaimsIdentity(
            result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role
        );

        identity.SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, Constants.Email)
            .SetClaim(Claims.Name, Constants.Name)
            .SetClaim("hotel", "Trivago")
            .SetClaims(Claims.Role, ["root", "admin"]);

        identity.SetDestinations(e => AuthorizationService.GetDestinations(identity, e));

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> LogoutPost()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return SignOut(
              authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
              properties: new AuthenticationProperties
              {
                  RedirectUri = "/"
              });
    }
}
