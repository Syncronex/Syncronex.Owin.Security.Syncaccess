using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
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
            return Redirect("index.html");
        }
    }
}