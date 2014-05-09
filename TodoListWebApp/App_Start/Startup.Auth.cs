using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using TodoListWebApp.DAL;
using TodoListWebApp.Models;
using AuthenticationContext = Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext;

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
            string Authority = "https://login.windows.net/common/";

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions { });
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    Client_Id = clientId,
                    Authority = Authority,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
                        // we inject our own multitenant validation logic
                        ValidateIssuer = false,
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                       AccessCodeReceived = (context) =>
                       {
                           var code = context.Code;

                           ClientCredential credential = new ClientCredential(clientId, appKey);
                           string tenantID = context.ClaimsIdentity.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid").Value;
                           string signedInUserID = context.ClaimsIdentity.FindFirst(ClaimTypes.NameIdentifier).Value;
                           AuthenticationContext authContext = new AuthenticationContext(string.Format("https://login.windows.net/{0}", tenantID));
                           AuthenticationResult result = authContext.AcquireTokenByAuthorizationCode(
                               code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, graphResourceID);

                           TokenCacheEntry tokenCacheEntry = new TokenCacheEntry
                           {
                               SignedInUser = signedInUserID,
                               TokenRequestorUser = result.UserInfo.UserId,
                               ResourceID = graphResourceID,
                               AccessToken = result.AccessToken,
                               RefreshToken = result.RefreshToken,
                               Expiration = result.ExpiresOn.AddMinutes(-5)
                           };
                           var existing = db.TokenCache.FirstOrDefault(a => (a.SignedInUser == signedInUserID) && (a.ResourceID == graphResourceID));
                           if (existing != null)
                           {
                               db.TokenCache.Remove(existing);
                           }

                           db.TokenCache.Add(tokenCacheEntry);
                           db.SaveChanges();
                           return Task.FromResult(0);
                        },
                        RedirectToIdentityProvider = (context) =>
                        {
                            // This ensures that the address used for sign in and sign out is picked up dynamically from the request
                            // this allows you to deploy your app (to Azure Web Sites, for example)without having to change settings
                            // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.
                            string appBaseUrl = context.Request.Scheme + "://" + context.Request.Host + context.Request.PathBase;
                            context.ProtocolMessage.Redirect_Uri = appBaseUrl + "/";
                            context.ProtocolMessage.Post_Logout_Redirect_Uri = appBaseUrl;
                            return Task.FromResult(0);
                        },
                        // we use this notification for injecting our custom logic after securitytoken has been validated
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
                            {
                                // the caller was neither from a trusted issuer or a registered user - throw to block the authentication flow
                                throw new System.IdentityModel.Tokens.SecurityTokenValidationException();
                            }

                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (context) =>
                        {
                            context.Redirect("/Home/Error");
                            return Task.FromResult(0);
                        }
                    }
                });
        }

    }
}