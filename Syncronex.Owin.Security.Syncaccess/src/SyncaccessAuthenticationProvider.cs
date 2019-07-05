using System;
using System.Threading.Tasks;

namespace Syncronex.Owin.Security.Syncaccess
{
    public interface ISyncaccessAuthenticationProvider
    {
        /// <summary>
        /// Gets or Sets the function that is called when the Authenticated method is called
        /// </summary>
        Func<SyncaccessAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or Sets the function that is called when the ReturnEndpoint method is invoked
        /// </summary>
        Func<SyncaccessReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever SyncAccess successfully authenticates a user
        /// </summary>
        Task Authenticated(SyncaccessAuthenticatedContext context);

        /// <summary>
        /// Invoked prioer to the ClaimsIdentity being saved in a local cookie and browser being
        /// redirected to the originally requested Url
        /// </summary>
        Task ReturnEndpoint(SyncaccessReturnEndpointContext context);
    }

    public class SyncaccessAuthenticationProvider : ISyncaccessAuthenticationProvider
    {
        public SyncaccessAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or Sets the function that is called when the Authenticated method is called
        /// </summary>
        public Func<SyncaccessAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or Sets the function that is called when the ReturnEndpoint method is invoked
        /// </summary>
        public Func<SyncaccessReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever SyncAccess successfully authenticates a user
        /// </summary>
        public virtual Task Authenticated(SyncaccessAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prioer to the ClaimsIdentity being saved in a local cookie and browser being
        /// redirected to the originally requested Url
        /// </summary>
        public virtual Task ReturnEndpoint(SyncaccessReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
