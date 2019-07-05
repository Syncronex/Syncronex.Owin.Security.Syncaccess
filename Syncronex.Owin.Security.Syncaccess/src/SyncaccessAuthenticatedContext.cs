using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class SyncaccessAuthenticatedContext : BaseContext
    {
        public SyncaccessAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            //TODO: verify the fields and move to constants
            UserId = TryGetValue(user, "UserId");
            Email = TryGetValue(user, "email");
        }
        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public string UserId { get; private set; }
        public string Email { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
