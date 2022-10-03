using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Owin;
using Syncronex.Owin.Security.Syncaccess;

namespace TestDriver
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            app.UseSyncaccessAuthentication(
                new SyncaccessAuthenticationOptions(ESyncAccessEnvironments.Production)
                {
                    ClientId = "testClient",
                    ClientSecret = "foobar88",
                    TenantId = "sync_robcom_dev",
                    Provider = new SyncaccessAuthenticationProvider()
                    {
                        OnAuthenticated = OnAuthenticated
                    }
                });
        }

        private Task OnAuthenticated(SyncaccessAuthenticatedContext arg)
        {
            System.Diagnostics.Debug.WriteLine(arg.RefreshToken);
            return Task.CompletedTask;
        }
    }
}