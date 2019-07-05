using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Default ctor creates new Authentication Options instance for
        /// production Identity server
        /// </summary>
        public SyncaccessAuthenticationOptions()
            : this(ESyncAccessEnvironments.Production)
        {
        }
        /// <summary>
        /// Use this ctor to setup dev/test environments
        /// Create a new instance of SyncaccessAuthenticationOptions for the
        /// given target environment. Environment controls the default Endpoints
        /// that are configured.
        /// </summary>
        public SyncaccessAuthenticationOptions(ESyncAccessEnvironments environment)
            : base(Constants.AuthenticationType)
        {
            CallbackPath = new PathString(Constants.DefaultCallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            Endpoints = new SyncaccessAuthenticationEndpoints(environment);
            AuthorizationServerTimeout = 5000;
        }
        /// <summary>
        /// The syncAccess tenantId to which this application is authenticating.
        /// </summary>
        public string TenantId { get; set; }
        /// <summary>
        /// Client Identifier that was provided during registration
        /// </summary>
        public string ClientId { get; set; }
        /// <summary>
        /// Client password that was provided during registration
        /// </summary>
        public string ClientSecret { get; set; }
        /// <summary>
        /// Target deployment environment
        /// </summary>
        public ESyncAccessEnvironments Environment { get; set; }
        /// <summary>
        /// Gets or sets the amount of time (miliseconds) we'll wait for
        /// api calls to the authorization server
        /// </summary>
        public int AuthorizationServerTimeout { get; set; }
        /// <summary>
        /// Gets or Sets the Oauth  endpoints used to authentication against syncAccess
        /// authorization server. You'd normally not need to override these
        /// </summary>
        public SyncaccessAuthenticationEndpoints Endpoints { get; set; }

        public SyncaccessAuthenticationProvider Provider { get; set; }
        /// <summary>
        /// The request path within the application's base path to which the
        /// user-agent is returned by the authorization server. The middleware
        /// processes this request when it arrives. Default value is "/signin-syncaccess"
        /// </summary>
        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the type used to encrypt sensitive data within the Middleware
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
