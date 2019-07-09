using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Syncronex.Owin.Security.Syncaccess
{
    /// <summary>
    /// Custom Authentication Handler used to interact with SyncAccess Authorization Server
    /// </summary>
    public class SyncaccessAuthenticationHandler : AuthenticationHandler<SyncaccessAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public SyncaccessAuthenticationHandler(ILogger logger, HttpClient httpClient)
        {
            //TODO: Make use of the logger
            _logger = logger;
            _httpClient = httpClient;
        }
        /// <summary>
        /// Main Owin Middleware entry point. This just delegates to the InvokeReplyPathAsync method
        /// </summary>
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }
        /// <summary>
        /// Called when Authorization server has redirect user back after a successful Authorization Code issuance.
        /// This is where we turn around and exchange the new authorization code for an access token and then
        /// fetch authenticated user information. This is ultimately called when the AuthenticateAsync function is called
        /// </summary>
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // This is where all the magic happens...
            // this is where we get the authorization code and then turn around and
            // exchange it for an access token
            AuthenticationProperties properties = null;
            try
            {
                var authorizationCodeResponseInfo = GetAuthorizationCodeInfoFromRequest(Request);

                properties = Options.StateDataFormat.Unprotect(authorizationCodeResponseInfo.State);
                if (properties == null)
                {
                    return null;
                }

                if (!ValidateCorrelationId(properties, _logger))
                {
                    return NullAuthenticationTicket(properties);
                }
                
                var accessTokenRequest = GetAccessTokenRequestMessage(authorizationCodeResponseInfo.AuthorizationCode,Request, Options);
                var tokenResponse = await _httpClient.SendAsync(accessTokenRequest);
                
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                var response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string) response.access_token;
                
                var account = await GetAccountInfoFromAuthorizationServer(accessToken, Request, Options);

                var context = GetNewAuthenticatedContext(account,properties, Context, accessToken, Options);

                await Options.Provider.Authenticated(context);
                
                return new AuthenticationTicket(context.Identity,context.Properties);
            }
            catch (Exception e)
            {
                _logger.WriteError(e.Message);
            }

            return NullAuthenticationTicket(properties);
        }

        /// <summary>
        /// Called to see if the current pipeline contains a Challenge Response that this
        /// middleware can process.  This is where we call out to authorization server
        /// to start the Authorization Code Grant process
        /// </summary>
        protected override Task ApplyResponseChallengeAsync()
        {
            var currentRequest = this.Request;
            var currentOptions = this.Options;
            var currentResponse = this.Response;

            if (currentResponse.StatusCode != 401)
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

            var scope = currentOptions.TenantId;
            var state = GetOAuthStateFromAuthenticationProperties(properties, currentOptions);

            var authorizationEndpoint = ConstructAuthorizationEndpoint(currentOptions, redirectUri, scope, state);

            currentResponse.Redirect(authorizationEndpoint);

            return Constants.EmptyCompletedTask;
        }

        /// <summary>
        /// Called to get the authenticated user from an Authorization Code. If the request is for
        /// /signin-syncaccess/ we expect that it's the redirect from the authorization server sending
        /// us an authorization code. We call the authenticateAsync method (which, in turn, calls AuthenticateCoreAsync
        /// which takes care of exchanging the auth code for an access token.  Once we've got an authenticated
        /// user, we ultimately redirect back to the external login sink that should have been setup in the
        /// options when the middleware was initialized
        /// </summary>
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!RequestIsExpectedSignInRequest(Request, Options)) return false;

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
                // Set the external cookie that will be used by the RedirectUri endpoint to get auth user
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
        private AuthenticationResponseChallenge CheckCurrentResponsePipelineForSyncAccessChallenge(AuthenticationOptions options)
        {
            var challenge = Helper.LookupChallenge(options.AuthenticationType, options.AuthenticationMode);
            return challenge;
        }
        /// <summary>
        /// helper to get the base portion of our current request Uri. Used to build up
        /// various links
        /// </summary>
        private static string GetBaseUri(IOwinRequest request)
        {
            return request.Scheme +
                Uri.SchemeDelimiter +
                request.Host +
                request.PathBase;
        }
        /// <summary>
        /// Get the Uri used in the current request. We use this as a fallback if the
        /// auth properties don't already designate a returnUri
        /// </summary>
        private static string GetCurrentUri(IOwinRequest request, string baseUri)
        {
            return baseUri +
                   request.Path +
                   request.QueryString;
        }
        /// <summary>
        /// Get the redirect Uri to which the Authorization server will send the user
        /// after successfully issuing the authorization code. Defaults to /signin-syncaccess
        /// </summary>
        private static string GetRedirectUri(SyncaccessAuthenticationOptions options, string baseUri)
        {
            return baseUri + options.CallbackPath;
        }
        /// <summary>
        /// ensure that we have a redirectUri. Set to current uri if one isn't set
        /// </summary>
        private static AuthenticationProperties CleanseCurrentAuthenticationProperties(AuthenticationProperties currentProperties,string currentUri)
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
        /// <summary>
        /// Build out the full Uri with query string for calling the Authorization Server's "Authorize" endpoint
        /// </summary>
        private static string ConstructAuthorizationEndpoint(SyncaccessAuthenticationOptions options,string redirectUri, string scope, string state)
        {
            return string.Format(Constants.AuthorizationUriTemplate,
                options.Endpoints.AuthorizationEndpoint,
                Uri.EscapeDataString(options.ClientId),
                Uri.EscapeDataString(redirectUri),
                Uri.EscapeDataString(scope),
                Uri.EscapeDataString(state)
            );
        }
        /// <summary>
        /// Helper to determine if the current request is one that we should be handling in this middleware. That means
        /// it's a request against our expected CallbackPath
        /// </summary>
        private static bool RequestIsExpectedSignInRequest(IOwinRequest request,SyncaccessAuthenticationOptions options)
        {
            return (options.CallbackPath.HasValue && options.CallbackPath == request.Path);
        }
        /// <summary>
        /// Called to get the authorization code and state off of the query string that was used
        /// in the redirect from the Auhtorization server
        /// </summary>
        private static AuthorizationCodeInfo GetAuthorizationCodeInfoFromRequest(IOwinRequest request)
        {
            string code = null;
            string state = null;

            var query = request.Query;
            var values = query.GetValues(Constants.AuthorizationCodeQueryParameterName);
            if (values != null && values.Count == 1)
            {
                code = values[0];
            }

            values = query.GetValues(Constants.StateQueryParameterName);
            if (values != null & values.Count == 1)
            {
                state = values[0];
            }

            return new AuthorizationCodeInfo()
            {
                AuthorizationCode = code,
                State = state
            };
        }
        private class AuthorizationCodeInfo
        {
            public string AuthorizationCode { get; set; }
            public string State { get; set; }
        }
        /// <summary>
        /// Get the POST body data for our call to token endpoint (to exchange authorization code
        /// for access token
        /// </summary>
        private static FormUrlEncodedContent GetTokenRequestBody(string authorizationCode,SyncaccessAuthenticationOptions options, string redirectUri)
        {
            var body = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type","authorization_code"),
                new KeyValuePair<string, string>("code", authorizationCode),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("client_id", options.ClientId),
                new KeyValuePair<string, string>("client_secret", options.ClientSecret)
            };

            return new FormUrlEncodedContent(body);
        }
        /// <summary>
        /// Get the return Uri that will be sent up to the Authorization server as part of the
        /// access token request.
        /// </summary>
        private static string GetTokenRequestRedirectUri(IOwinRequest request, SyncaccessAuthenticationOptions options)
        {
            var requestPrefix = request.Scheme + "://" + request.Host;
            return requestPrefix + request.PathBase + options.CallbackPath;
        }
        /// <summary>
        /// Gets the fully-formed Token Request that will be sent to authorization server
        /// </summary>
        private static HttpRequestMessage GetAccessTokenRequestMessage(string authorizationCode, IOwinRequest request, SyncaccessAuthenticationOptions options)
        {
            var redirectUri = GetTokenRequestRedirectUri(request, options);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, options.Endpoints.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = GetTokenRequestBody(authorizationCode,
                options, redirectUri);

            return requestMessage;
        }
        /// <summary>
        /// Called to fetch authenticated user details from the authorization server given an
        /// access token
        /// </summary>
        private async Task<JObject> GetAccountInfoFromAuthorizationServer(string accessToken, IOwinRequest request,SyncaccessAuthenticationOptions options)
        {
            var accountRequest = new HttpRequestMessage(HttpMethod.Get, options.Endpoints.UserInfoEndpoint );
            accountRequest.Headers.Authorization = new AuthenticationHeaderValue("bearer",accessToken);
            accountRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            var accountResponse = await _httpClient.SendAsync(accountRequest, request.CallCancelled);
            accountResponse.EnsureSuccessStatusCode();
            var text = await accountResponse.Content.ReadAsStringAsync();
            var account = JObject.Parse(text);

            return account;
        }
        /// <summary>
        /// Called to build up the authenticated context once we've received account details from the authorization
        /// server.
        /// </summary>
        private SyncaccessAuthenticatedContext GetNewAuthenticatedContext(JObject account,AuthenticationProperties properties ,IOwinContext owinContext, string accessToken,AuthenticationOptions options)
        {
            var context = new SyncaccessAuthenticatedContext(owinContext,account,accessToken)
            {
                Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType
                )
            };

            if (!string.IsNullOrEmpty(context.AccountId))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier,context.AccountId,"",options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(context.Email))
            {
                context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType,context.Email,"",options.AuthenticationType));
                context.Identity.AddClaim(new Claim(ClaimTypes.Email,context.Email,"",options.AuthenticationType));
            }

            context.Properties = properties;

            return context;
        }
        /// <summary>
        /// Helper function called to return a 'null' Authentication Ticket (aka failed response)
        /// </summary>
        private static AuthenticationTicket NullAuthenticationTicket(AuthenticationProperties properties)
        {
            return new AuthenticationTicket(null,properties);
        }
    }
}
