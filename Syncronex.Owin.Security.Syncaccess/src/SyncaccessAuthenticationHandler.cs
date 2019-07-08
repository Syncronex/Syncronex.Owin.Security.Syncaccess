using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.SqlServer.Server;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessAuthenticationHandler : AuthenticationHandler<SyncaccessAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

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
                
                var accountRequest = new HttpRequestMessage(HttpMethod.Get, Options.Endpoints.UserInfoEndpoint );
                accountRequest.Headers.Authorization = new AuthenticationHeaderValue("bearer",accessToken);
                accountRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var accountResponse = await _httpClient.SendAsync(accountRequest, Request.CallCancelled);
                accountResponse.EnsureSuccessStatusCode();
                text = await accountResponse.Content.ReadAsStringAsync();
                var account = JObject.Parse(text);

                

                //  7. Build up the Claims Identity with data from step 6
                var context = new SyncaccessAuthenticatedContext(Context,account,accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType
                        )
                };

                if (!string.IsNullOrEmpty(context.AccountId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier,context.AccountId,"",Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType,context.Email,"",Options.AuthenticationType));
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email,context.Email,"",Options.AuthenticationType));
                }

                context.Properties = properties;
                await Options.Provider.Authenticated(context);
                return new AuthenticationTicket(context.Identity,context.Properties);
            }
            catch (Exception e)
            {
                _logger.WriteError(e.Message);
            }
            return new AuthenticationTicket(null,properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            var currentRequest = this.Request;
            var currentOptions = this.Options;

            if (Response.StatusCode != 401)
            {
                return Constants.EmptyCompletedTask;
            }

            var challenge = CheckCurrentResponsePipelineForSyncAccessChallenge(currentOptions);
            if (challenge == null) return Constants.EmptyCompletedTask;

            var baseUri = GetBaseUri(currentRequest);
            var currentUri = GetCurrentUri(currentRequest, baseUri);
            var redirectUri = GetRedirectUri(currentOptions, baseUri);

            var properties = CleanseCurrentAuthenticationProperties(challenge.Properties, currentUri);
            
            AddCorrelationIdToCurrentAuthenticationProperties(properties);

            var scope = Options.TenantId;
            var state = GetOAuthStateFromAuthenticationProperties(properties, currentOptions);

            var authorizationEndpoint = ConstructAuthorizationEndpoint(currentOptions, redirectUri, scope, state);

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

        /// <summary>
        /// Examine the current response in the pipeline to see if it contains a Challenge Response
        /// that the syncAccessAuthenticationHandler can 'handle'.
        /// </summary>
        private AuthenticationResponseChallenge CheckCurrentResponsePipelineForSyncAccessChallenge(
            SyncaccessAuthenticationOptions options)
        {
            var challenge = Helper.LookupChallenge(options.AuthenticationType, options.AuthenticationMode);
            return challenge;
        }

        private static string GetBaseUri(IOwinRequest request)
        {
            return request.Scheme +
                Uri.SchemeDelimiter +
                request.Host +
                request.PathBase;
        }

        private static string GetCurrentUri(IOwinRequest request, string baseUri)
        {
            return baseUri +
                   request.Path +
                   request.QueryString;
        }

        private static string GetRedirectUri(SyncaccessAuthenticationOptions options, string baseUri)
        {
            return baseUri + options.CallbackPath;
        }

        private static AuthenticationProperties CleanseCurrentAuthenticationProperties(
            AuthenticationProperties currentProperties,string currentUri)
        {
            if (string.IsNullOrEmpty(currentProperties.RedirectUri))
            {
                currentProperties.RedirectUri = currentUri;
            }

            return currentProperties;
        }

        /// <summary>
        /// Part of oAuth specification to guard against CSRF attacks.
        /// See https://tools.ietf.org/html/rfc6749#section-10.12
        /// </summary>
        private void AddCorrelationIdToCurrentAuthenticationProperties(AuthenticationProperties properties)
        {
            GenerateCorrelationId(properties);
        }
        /// <summary>
        /// Serialize and encrypt our current Authentication properties to send as our 'state'
        /// param to the oAuth server
        /// </summary>
        /// <remarks>
        /// Remember that the oAuth spec requires an authorization server to return the 'state' data
        /// back to us (unchanged) as part of any redirect.
        /// </remarks>
        private static string GetOAuthStateFromAuthenticationProperties(AuthenticationProperties properties, SyncaccessAuthenticationOptions options)
        {
            return options.StateDataFormat.Protect(properties);
        }

        private static string ConstructAuthorizationEndpoint(SyncaccessAuthenticationOptions options,
            string redirectUri, string scope, string state)
        {
            return string.Format(Constants.AuthorizationUriTemplate,
                options.Endpoints.AuthorizationEndpoint,
                Uri.EscapeDataString(options.ClientId),
                Uri.EscapeDataString(redirectUri),
                Uri.EscapeDataString(scope),
                Uri.EscapeDataString(state)
            );
        }
    }
}
