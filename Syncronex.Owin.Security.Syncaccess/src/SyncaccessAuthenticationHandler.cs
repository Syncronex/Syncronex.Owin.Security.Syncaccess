using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessAuthenticationHandler : AuthenticationHandler<SyncaccessAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public SyncaccessAuthenticationHandler(ILogger logger, HttpClient httpClient)
        {
            _logger = logger;
            _httpClient = httpClient;
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // This is where all the magic happens...
            // this is where we get the authorization code and then turn around and
            // exchange it for an access token

            AuthenticationProperties properties = null;
            try
            {
                //  1. Pull the authorization code and state off of the incoming request
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (values != null & values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }
                //  2. Validate CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null,properties);
                }
                //  3. Build up the token request
                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type","authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };
                //  4. Make the token request
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                //  5. Handle the token response
                var tokenResponse = await _httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string) response.access_token;
                //  6. (assuming valid token) Fetch user data from IDP
                // our initial token response contains user info...use that for now until we have a /user endpoint to hit
                var refreshToken = (string) response.refresh_token;
                var userEmail = (string) response["syncaccess:username"];

                //  7. Build up the Claims Identity with data from step 6
                
            }
            catch (Exception e)
            {
                _logger.WriteError(e.Message);
            }
            return new AuthenticationTicket(null,properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            // TODO: refactor and cleanup the code
            // This is where we put the code that redirects the user to the Authorization
            // server's 'authorize' endpoint
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null) return Task.FromResult<object>(null);

            var baseUri = Request.Scheme +
                          Uri.SchemeDelimiter +
                          Request.Host +
                          Request.PathBase;
            var currentUri = baseUri +
                             Request.Path +
                             Request.QueryString;
            var redirectUri = baseUri + Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            GenerateCorrelationId(properties);  // OAuth2 10.12 CSRF

            var scope = Options.TenantId;
            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint = Options.Endpoints.AuthorizationEndpoint +
                                        "?response_type=code" +
                                        "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                                        "&scope=" + Uri.EscapeDataString(scope) +
                                        "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            // modled this after https://github.com/TerribleDev/OwinOAuthProviders/blob/master/src/Owin.Security.Providers.GitHub/GitHubAuthenticationHandler.cs
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new SyncaccessReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType,
                    StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType,
                        grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties,grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }
    }
}
