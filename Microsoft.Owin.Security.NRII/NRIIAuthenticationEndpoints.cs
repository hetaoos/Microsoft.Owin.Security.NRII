using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.NRII.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.NRII
{
    public class NRIIAuthenticationOptions : AuthenticationOptions
    {
        public class NRIIAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request NRII access
            /// </summary>
            /// <remarks>
            /// Defaults to https://218.249.73.245/instru_war/oauth2/authorize.ins
            /// </remarks>
            public string AuthorizationEndPoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://218.249.73.245/instru_war/oauth2/access_token.ins
            /// </remarks>
            public string TokenEndPoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults to https://218.249.73.245/instru_war/oauth2/resource/userinfo.ins
            /// </remarks>
            public string UserInfoEndPoint { get; set; }

            public NRIIAuthenticationEndpoints()
            {
                AuthorizationEndPoint = "https://218.249.73.245/instru_war/oauth2/authorize.ins";
                TokenEndPoint = "https://218.249.73.245/instru_war/oauth2/access_token.ins";
                UserInfoEndPoint = "https://218.249.73.245/instru_war/oauth2/resource/userinfo.ins";

            }
            /// <summary>
            /// 返回测试地址
            /// </summary>
            /// <returns></returns>
            public static NRIIAuthenticationEndpoints CreateTestNRIIAuthenticationEndpoints()
            {
                return new NRIIAuthenticationEndpoints()
                {
                    AuthorizationEndPoint = "http://218.249.73.248:8080/OAuthServer/oauth2/authorize.ins",
                    TokenEndPoint = "https://218.249.73.248/OAuthServer/oauth2/access_token.ins",
                    UserInfoEndPoint = "https://218.249.73.248/OAuthServer/oauth2/resource/userinfo.ins",
                };
            }
        }


        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to NRII
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with NRII.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with NRII.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/sign-in".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the NRII supplied Application Id
        /// </summary>
        public string AppId { get; set; }

        /// <summary>
        ///     Gets or sets the NRII supplied Application Secret
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against NRII.
        /// authentication.
        /// </summary>
        public NRIIAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="INRIIAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public INRIIAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }


        /// <summary>
        ///     Initializes a new <see cref="NRIIAuthenticationOptions" />
        /// </summary>
        public NRIIAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString($"/signin-{Constants.DefaultAuthenticationType}");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "read"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new NRIIAuthenticationEndpoints();
            Caption = "国家大仪平台";
        }
    }
}
