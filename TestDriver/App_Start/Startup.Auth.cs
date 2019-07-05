﻿using System;
using System.Collections.Generic;
using System.Linq;
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
                new SyncaccessAuthenticationOptions(ESyncAccessEnvironments.Dev)
                {
                    ClientId = "adm_sync_robcom_dev",
                    ClientSecret = "foobar88",
                    TenantId = "sync_robcom_dev"
                });
        }

    }
}