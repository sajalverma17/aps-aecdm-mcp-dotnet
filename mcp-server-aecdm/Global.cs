using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace mcp_server_aecdm
{
	public static class Global
	{
		public static Random random = new Random();
		public static string AccessToken { get; set; }
		public static string RefreshToken { get; set; }
		public static string ClientId { get; set; }
		public static string ClientSecret { get; set; }
		public static string CallbackURL { get; set; }
		public static string Scopes { get; set; }
		public static string codeVerifier { get; set; }
		public static WebSocket _webSocket = null;
	}
}
