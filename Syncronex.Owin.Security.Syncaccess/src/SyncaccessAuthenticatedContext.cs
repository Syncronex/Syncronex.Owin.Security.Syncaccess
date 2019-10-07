using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Syncronex.Owin.Security.Syncaccess
{
    /// <summary>
    /// Represents authenticated user account details provided by the Authorization Server.
    /// </summary>
    public class SyncaccessAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Create an instance of the SyncaccessAuthenticationContext
        /// </summary>
        /// <param name="context">Base OwinContext from which this object derives</param>
        /// <param name="account">Dynamic object representing the returned response from the IDP</param>
        /// <param name="accessToken">The access token that was used to fetch the account details.</param>
        /// <param name="refreshToken">The refresh token that was returned from the token endpoint call</param>
        public SyncaccessAuthenticatedContext(IOwinContext context, JObject account, string accessToken, string refreshToken)
            : base(context)
        {
            Account = account;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            AccountId = TryGetValue(account, Constants.SyncaccessAccountUniqueIdentifierKey);
            Email = TryGetValue(account, Constants.SyncaccessAccountEmailAddressKey);
        }
        /// <summary>
        /// Get the complete response object returned by the /account/ endpoint.
        /// </summary>
        public JObject Account { get; private set; }
        /// <summary>
        /// Get the access token that was used to fetch the account data
        /// </summary>
        public string AccessToken { get; private set; }
        /// <summary>
        /// Get the refresh token (if present) that was created during the auth code-for-token exchange
        /// </summary>
        public string RefreshToken { get; private set; }
        /// <summary>
        /// Gets the unique identifier used by the authorization server to identify the given
        /// account
        /// </summary>
        public string AccountId { get; private set; }
        /// <summary>
        /// Get the email address that is assigned to the account
        /// </summary>
        public string Email { get; private set; }
        /// <summary>
        /// Get and Set the ClaimsIdentity object that will encode the account details
        /// </summary>
        public ClaimsIdentity Identity { get; set; }
        /// <summary>
        /// Get and set the authentication properties collection
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>
        /// Helper method to extract data from the returned account response
        /// </summary>
        private static string TryGetValue(JObject account, string propertyName)
        {
            return account.TryGetValue(propertyName, out var value) ? value.ToString() : null;
        }
    }
}
