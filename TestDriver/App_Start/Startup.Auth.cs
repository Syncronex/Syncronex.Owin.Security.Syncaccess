using Microsoft.AspNet.Identity;
using Owin;
using Syncronex.Owin.Security.Syncaccess;
using TestDriver.Factories;

namespace TestDriver
{
    public partial class Startup
    {
        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            app.UseSyncaccessAuthentication(new AuthenticationOptionsFactory().GetOptions());
        }
    }
}