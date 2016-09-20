using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.NRII.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class NRIIAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="NRIIAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">NRII Access token</param>
        public NRIIAuthenticatedContext(IOwinContext context, JObject user, string accessToken, int expiresIn)
            : base(context)
        {
            AccessToken = accessToken;
            User = user;
            ExpiresIn = TimeSpan.FromSeconds(expiresIn);
            Id = TryGetValue(user, "nickname");
            Name = TryGetValue(user, "username");
            Email = TryGetValue(user, "email");
            Institution = TryGetValue(user, "institution");
            UnitType = TryGetValue(user, "unittype");
            TechField = TryGetValue(user, "tech_field");
            Title = TryGetValue(user, "title");
            Phone = TryGetValue(user, "phone");
            //Alias = TryGetValue(user, "phone");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the NRII user obtained from the endpoint https://graph.qq.com/oauth2.0/me
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the NRII OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the NRII access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Get the user's id
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Get the user's displayName
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Get the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Get the user's publicAlias
        /// </summary>
        public string Alias { get; private set; }

        /// <summary>
        /// Get the user's institution
        /// </summary>
        public string Institution { get; private set; }

        /// <summary>
        /// Get the user's unittype
        /// </summary>
        public string UnitType { get; private set; }

        /// <summary>
        /// Get the user's tech_field
        /// </summary>
        public string TechField { get; private set; }

        /// <summary>
        /// Get the user's title
        /// </summary>
        public string Title { get; private set; }

        /// <summary>
        /// Get the user's phone
        /// </summary>
        public string Phone { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
