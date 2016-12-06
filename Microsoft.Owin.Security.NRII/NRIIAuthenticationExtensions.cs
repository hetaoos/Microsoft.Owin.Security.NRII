using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Owin;
using static Microsoft.Owin.Security.NRII.NRIIAuthenticationOptions;

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
        /// <summary>
        /// NRII： 使用正式接口
        /// </summary>
        /// <param name="app"></param>
        /// <param name="appId"></param>
        /// <param name="appSecret"></param>
        /// <returns></returns>
        public static IAppBuilder UseNRIIAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseNRIIAuthentication(new NRIIAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret
            });
        }
        /// <summary>
        /// NRII： 使用测试接口
        /// </summary>
        /// <param name="app"></param>
        /// <param name="appId"></param>
        /// <param name="appSecret"></param>
        /// <returns></returns>
        public static IAppBuilder UseNRIIAuthenticationTest(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UseNRIIAuthentication(new NRIIAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret,
                Endpoints = NRIIAuthenticationEndpoints.CreateTestNRIIAuthenticationEndpoints(),
            });
        }
    }
}
