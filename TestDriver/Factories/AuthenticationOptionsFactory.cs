using System.Threading.Tasks;
using Syncronex.Owin.Security.Syncaccess;

namespace TestDriver.Factories
{
    public class AuthenticationOptionsFactory
    {
        public SyncaccessAuthenticationOptions GetOptions()
        {
            return new SyncaccessAuthenticationOptions(ESyncAccessEnvironments.Dev)
            {
                ClientId = "adm_sync_robcom_dev",
                ClientSecret = "foobar88",
                TenantId = "sync_robcom_dev",
                Provider = new SyncaccessAuthenticationProvider()
                {
                    OnAuthenticated = OnAuthenticated
                }
            };
        }

        private static Task OnAuthenticated(SyncaccessAuthenticatedContext arg)
        {
            System.Diagnostics.Debug.WriteLine(arg.RefreshToken);
            return Task.CompletedTask;
        }

    }
}