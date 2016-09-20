using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.NRII.Provider
{
    public class NRIIReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public NRIIReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
