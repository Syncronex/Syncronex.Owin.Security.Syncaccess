using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Syncronex.Owin.Security.Syncaccess
{
    public static class Constants
    {
        public const string AuthenticationType = "Syncronex.syncAccess";
        public const string DefaultCallbackPath = "/signin-syncaccess/";

        internal const string DefaultAuthorizationEndpointTemplate = "https://identity{0}.syncronex.com/oauth/authorize";
        internal const string DefaultTokenEndpointTemplate = "https://identity{0}.syncronex.com/oauth/token";
        internal const string DefaultAccountInfoEndpointTemplate = "https://identity{0}.syncronex.com/api/v1/account";

        internal const string DevEnvironmentString = ".dev";
        internal const string StageEnvironmentString = ".stage";
        internal const string ProdEnvironmentString = ""; // in production systems, the env portion of url is omitted

    }
}
