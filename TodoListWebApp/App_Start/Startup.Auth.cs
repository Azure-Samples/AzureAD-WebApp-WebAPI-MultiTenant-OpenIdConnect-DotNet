using Microsoft.Owin.Security.Cookies;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System.Threading.Tasks;
using System.Configuration;
using TodoListWebApp.DAL;
using System.IdentityModel.Claims;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using TodoListWebApp.Models;

namespace TodoListWebApp
{

    public partial class Startup
    {
        private TodoListWebAppContext db = new TodoListWebAppContext();
        public void ConfigureAuth(IAppBuilder app)
        {         
            string clientId = ConfigurationManager.AppSettings["ida:ClientID"];
            string appKey = ConfigurationManager.AppSettings["ida:Password"];
            string graphResourceID = "https://graph.windows.net";
            //fixed address for multitenant apps in the public cloud
            string Authority = "https://login.microsoftonline.com/common/";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = Authority,
                    TokenValidationParameters = new System.IdentityModel.Tokens.TokenValidationParameters
                    {
                        // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
                        // we inject our own multitenant validation logic
                        ValidateIssuer = false,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        AuthorizationCodeReceived = async (context) =>
                        {
                            var code = context.Code;

                            ClientCredential credential = new ClientCredential(clientId, appKey);
                            string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                            // Remember that some Cloud based reverse proxies will change https to http on your context.Request.Scheme
                            //    Add substitution or replace("http://","https://") to context.Properties.RedirectUri
                            //    if this applies to your hosting situation. This secondary http to https fix is needed
                            //    for form-post then redirect OAuth authentication methods

                            AuthenticationContext authContext = new AuthenticationContext(string.Format("https://login.microsoftonline.com/{0}", tenantID), new EFADALTokenCache(signedInUserID));
                            AuthenticationResult result = await authContext.AcquireTokenByAuthorizationCodeAsync(
                                code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceID);
                        },
                        RedirectToIdentityProvider = (context) =>
                        {
                            // This ensures that the address used for sign in and sign out is picked up dynamically from the request
                            // this allows you to deploy your app (to Azure Web Sites, for example)without having to change settings
                            // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.
                            string appBaseUrl = context.Request.Scheme + "://" + context.Request.Host + context.Request.PathBase;
                            // Remember that some Cloud based reverse proxies will change https to http on your context.Request.Scheme
                            //    Add substitution or replace("http://","https://") to context.ProtocolMessage.RedirectUri
                            //    if this applies to your hosting situation
                            context.ProtocolMessage.RedirectUri = appBaseUrl + "/";
                            context.ProtocolMessage.PostLogoutRedirectUri = appBaseUrl;
                            return Task.FromResult(0);
                        },
                        // we use this notification for injecting our custom logic
                        SecurityTokenValidated = (context) =>
                        {
                            // retriever caller data from the incoming principal
                            string issuer = context.AuthenticationTicket.Identity.FindFirst("iss").Value;
                            string UPN = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.Name).Value;
                            string tenantID = context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;

                            if (
                                // the caller comes from an admin-consented, recorded issuer
                                (db.Tenants.FirstOrDefault(a => ((a.IssValue == issuer) && (a.AdminConsented))) == null)
                                // the caller is recorded in the db of users who went through the individual onboardoing
                                && (db.Users.FirstOrDefault(b => ((b.UPN == UPN) && (b.TenantID == tenantID))) == null)
                                )
                                // the caller was neither from a trusted issuer or a registered user - throw to block the authentication flow
                                throw new System.IdentityModel.Tokens.SecurityTokenValidationException();
                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (context) =>
                        {
                            context.OwinContext.Response.Redirect("/Home/Error");
                            context.HandleResponse(); // Suppress the exception
                            return Task.FromResult(0);
                        }
                    }
                });

        }

    }
}
