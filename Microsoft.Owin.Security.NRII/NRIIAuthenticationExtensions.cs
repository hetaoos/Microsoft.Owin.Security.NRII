using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Owin;


namespace Microsoft.Owin.Security.NRII
{
    public static class NRIIAuthenticationExtensions
    {
        public static IAppBuilder UseNRIIAuthentication(this IAppBuilder app, NRIIAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            app.Use(typeof(NRIIAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseNRIIAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseNRIIAuthentication(new NRIIAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret
            });
        }
    }
}
