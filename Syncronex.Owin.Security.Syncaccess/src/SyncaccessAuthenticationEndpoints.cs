using System;

namespace Syncronex.Owin.Security.Syncaccess
{
    /// <summary>
    /// Various https endpoints used to support the Syncaccess Authorization process.
    /// </summary>
    public class SyncaccessAuthenticationEndpoints
    {
        public SyncaccessAuthenticationEndpoints(ESyncAccessEnvironments environment)
        {
            var envString = GetEnvironmentStringFromEnvironment(environment);

            AuthorizationEndpoint = string.Format(Constants.DefaultAuthorizationEndpointTemplate, envString);
            TokenEndpoint = string.Format(Constants.DefaultTokenEndpointTemplate, envString);
            UserInfoEndpoint = string.Format(Constants.DefaultAccountInfoEndpointTemplate, envString);
        }

        /// <summary>
        /// Endpoint to which a user is redirected to get an Authorization code from the
        /// Authorization server.  Defaults to https://identity.syncronex.com/oauth/authorize
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Endpoint used to exchange authorization codes for access tokens or to which client
        /// credentials and resourceownercredentials grants are directed. Defaults to
        /// https://identity.syncronex.com/oauth/token
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Endpoint used to fetch specific user data given a proper authentication token
        /// defaults to https://identity.syncronex.com/api/user
        /// </summary>
        public string UserInfoEndpoint { get; set; }

        private static string GetEnvironmentStringFromEnvironment(ESyncAccessEnvironments environment)
        {
            switch (environment)
            {
                case ESyncAccessEnvironments.Dev:
                    return Constants.DevEnvironmentString;
                case ESyncAccessEnvironments.Stage:
                    return Constants.StageEnvironmentString;
                case ESyncAccessEnvironments.Production:
                    return Constants.ProdEnvironmentString;
                default:
                    throw new ArgumentException("Unexpected enum value provided to GetEnvironmentStringFromEnvironment");
            }
        }
    }
}
