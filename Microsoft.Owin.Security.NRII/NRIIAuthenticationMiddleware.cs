using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.NRII.Provider;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Owin;

namespace Microsoft.Owin.Security.NRII
{
    public class NRIIAuthenticationMiddleware : AuthenticationMiddleware<NRIIAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;


        public NRIIAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, NRIIAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.AppId))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientId"));
            if (String.IsNullOrWhiteSpace(Options.AppSecret))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientSecret"));

            logger = app.CreateLogger<NRIIAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new NRIIAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(NRIIAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v2");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10,
            };
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("NRII middleware");
            httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Microsoft.Owin.Security.NRII.NRIIAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<NRIIAuthenticationOptions> CreateHandler()
        {
            return new NRIIAuthenticationHandler(httpClient, logger);
        }

        private HttpMessageHandler ResolveHttpMessageHandler(NRIIAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
