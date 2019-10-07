using System.Threading.Tasks;

namespace Syncronex.Owin.Security.Syncaccess
{
    public static class Constants
    {
        public const string AuthenticationType = "Syncronex.syncAccess";
        public const string DefaultCallbackPath = "/signin-syncaccess/";
        public const string SyncaccessAccountUniqueIdentifierKey = "id";
        public const string SyncaccessAccountEmailAddressKey = "emailAddress";



        internal const string DefaultAuthorizationEndpointTemplate = "https://identity{0}.syncronex.com/oauth/authorize";
        internal const string DefaultTokenEndpointTemplate = "https://identity{0}.syncronex.com/oauth/token";
        internal const string DefaultAccountInfoEndpointTemplate = "https://identity{0}.syncronex.com/api/v1/account";

        internal const string DevEnvironmentString = ".dev";
        internal const string StageEnvironmentString = ".stage";
        internal const string ProdEnvironmentString = ""; // in production systems, the env portion of url is omitted

        internal const string AccessTokenClaimType = "access_token";
        internal const string RefreshTokenClaimType = "refresh_token";

        /// <summary>
        /// Uri template for making oAuth 'Authorization Code' request to the oAuth server
        /// </summary>
        internal const string AuthorizationUriTemplate = "{0}?response_type=code&client_id={1}&redirect_uri={2}&scope={3}&state={4}";

        internal const string AuthorizationCodeQueryParameterName = "code";
        internal const string StateQueryParameterName = "state";

        internal static Task EmptyCompletedTask => Task.FromResult<object>(null);
    }
}
