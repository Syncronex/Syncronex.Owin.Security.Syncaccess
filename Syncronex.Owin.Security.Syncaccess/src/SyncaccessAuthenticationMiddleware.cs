using System;
using System.Net.Http;
using System.Runtime.InteropServices;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessAuthenticationMiddleware : AuthenticationMiddleware<SyncaccessAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public SyncaccessAuthenticationMiddleware(OwinMiddleware next,IAppBuilder app,
            SyncaccessAuthenticationOptions options) 
            : base(next, options)
        {
            _logger = app.CreateLogger<SyncaccessAuthenticationMiddleware>();
            if(Options.Provider == null)
                Options.Provider = new SyncaccessAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(SyncaccessAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient()
            {
                Timeout = TimeSpan.FromMilliseconds(Options.AuthorizationServerTimeout),
                MaxResponseContentBufferSize = 1024*1024*10
            };

            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Syncronex Owin syncAccess middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        protected override AuthenticationHandler<SyncaccessAuthenticationOptions> CreateHandler()
        {
            return new SyncaccessAuthenticationHandler(_logger,_httpClient);
        }

    }
}
