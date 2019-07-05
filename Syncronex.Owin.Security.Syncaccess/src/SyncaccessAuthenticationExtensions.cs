using Owin;
using Seterlund.CodeGuard;

namespace Syncronex.Owin.Security.Syncaccess
{
    /// <summary>
    /// Extension methods to make setup of Syncaccess Middleware easier
    /// </summary>
    public static class SyncaccessAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users via the SyncAccess Authorization Server
        /// </summary>
        public static IAppBuilder UseSyncaccessAuthentication(this IAppBuilder app, SyncaccessAuthenticationOptions options)
        {
            Guard.That(app).IsNotNull();
            Guard.That(options).IsNotNull();

            app.Use(typeof(SyncaccessAuthenticationMiddleware), app, options);
            return app;
        }
    }
}
