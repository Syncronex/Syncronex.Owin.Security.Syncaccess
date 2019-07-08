using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json;
using TestDriver.oauth;

namespace TestDriver.Controllers
{
    [Authorize]
    public class AccountController:Controller
    {
        public async Task<ActionResult> Login()
        {
            return View();
        }
        [AllowAnonymous]
        //[ValidateAntiForgeryToken]
        public async Task<ActionResult> LoginExternal()
        {
            return new ChallengeResult("Syncronex.syncAccess",
                Url.Action("ExternalLoginCallback"));
        }
        [AllowAnonymous]
        [HttpGet]
        public async Task<ActionResult> ExternalLoginCallback()
        {
            var authManager = Request.GetOwinContext().Authentication;
            var loginInfo = await authManager.GetExternalLoginInfoAsync();
            if (loginInfo == null) return View();

            var simpleModel = new ExternalLoginViewModel(loginInfo);
            var jsonResult = JsonConvert.SerializeObject(simpleModel, Formatting.Indented);

            ViewData["SerializedLoginInfo"] = jsonResult;

            return View();
        }

        public class ExternalLoginViewModel
        {
            public ExternalLoginViewModel(ExternalLoginInfo loginInfo)
            {
                Provider = loginInfo.Login.LoginProvider;
                ProviderKey = loginInfo.Login.ProviderKey;
                DefaultUsername = loginInfo.DefaultUserName;
                Email = loginInfo.Email;
                ExternalIdentityAuthType = loginInfo.ExternalIdentity.AuthenticationType;
                ExternalIdentityNameclaimType = loginInfo.ExternalIdentity.NameClaimType;
                ExternalIdentityRoleClaimType = loginInfo.ExternalIdentity.RoleClaimType;

                foreach (var externalIdentityClaim in loginInfo.ExternalIdentity.Claims)
                {
                    if(ExternalIdentityClaims == null) ExternalIdentityClaims = new Dictionary<string, string>();

                    ExternalIdentityClaims.Add(externalIdentityClaim.Type,externalIdentityClaim.Value);
                }
            }

            public string ProviderKey { get; }
            public string Provider { get; }
            public string DefaultUsername { get; }
            public string Email { get; }
            public string ExternalIdentityAuthType { get; }
            public string ExternalIdentityNameclaimType { get; }
            public string ExternalIdentityRoleClaimType { get; }


            public Dictionary<string,string> ExternalIdentityClaims { get; }
        }
    }
}