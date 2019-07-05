using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessReturnEndpointContext : ReturnEndpointContext
    {
        public SyncaccessReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) 
            : base(context, ticket)
        {
        }
    }
}
