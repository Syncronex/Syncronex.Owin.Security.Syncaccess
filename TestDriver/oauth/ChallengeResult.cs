using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;

namespace TestDriver.oauth
{
    public class ChallengeResult : HttpUnauthorizedResult
    {
        private const string XsrfKey = "Xsrf_Key";

        public ChallengeResult(string provider, string redirectUri, string userId)
        {
            AuthenticationProvider = provider;
            RedirectUri = redirectUri;
            UserId = userId;
        }
        public ChallengeResult(string provider, string redirectUri)
        :this(provider,redirectUri,null)
        {
        }

        public string AuthenticationProvider { get; }
        public string RedirectUri { get; }
        public string UserId { get; }

        public override void ExecuteResult(ControllerContext context)
        {
            var properties = new AuthenticationProperties()
            {
                RedirectUri = RedirectUri
            };
            if (UserId != null)
            {
                properties.Dictionary[XsrfKey] = UserId;
            }

            var owin = context.HttpContext.GetOwinContext();
            owin.Authentication.Challenge(properties,AuthenticationProvider);
        }

    }
}