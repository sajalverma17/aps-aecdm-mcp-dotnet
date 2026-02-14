using ModelContextProtocol.Server;
using System.ComponentModel;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Text;
using System.Web;
using System.Security.Cryptography;

namespace mcp_server_aecdm.Tools;

[McpServerToolType]
public static class AuthTools
{
	private const string BASE_URL = "https://developer.api.autodesk.com/aec/graphql";

	[McpServerTool, Description("Get the token from the user")]
	public static async Task<string> GetToken()
	{
		await GenerateAPSToken();
		return $"Token generated: {Global.AccessToken}";
	}

	[McpServerTool, Description("Get the token from the user using Authorization Code flow with client secret (confidential client)")]
	public static async Task<string> GetTokenConfidential()
	{
		await GenerateAPSTokenConfidential();
		return $"Token generated: {Global.AccessToken}";
	}

	public static async Task GenerateAPSToken()
	{
		string codeVerifier = RandomString(64);
		string codeChallenge = GenerateCodeChallenge(codeVerifier);
		Global.codeVerifier = codeVerifier;
		//read client id from env variable
		Global.ClientId = Environment.GetEnvironmentVariable("CLIENT_ID");
		Global.ClientSecret = null;
		Global.CallbackURL = "http://localhost:8080/";
		Global.Scopes = "data:read";
		await redirectToLogin(codeChallenge);
	}

	public static async Task GenerateAPSTokenConfidential()
	{
		string codeVerifier = RandomString(64);
		string codeChallenge = GenerateCodeChallenge(codeVerifier);
		Global.codeVerifier = codeVerifier;
		Global.ClientId = Environment.GetEnvironmentVariable("CLIENT_ID");
		Global.ClientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
		Global.CallbackURL = Environment.GetEnvironmentVariable("CALLBACK_URL");
		Global.Scopes = "data:read";
		await redirectToLoginConfidential(codeChallenge);
	}

	static async Task redirectToLogin(string codeChallenge)
	{
		string[] prefixes =
		{
				Global.CallbackURL
			};

		System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
		{
			FileName = $"https://developer.api.autodesk.com/authentication/v2/authorize?response_type=code&client_id={Global.ClientId}&redirect_uri={HttpUtility.UrlEncode(Global.CallbackURL)}&scope={Global.Scopes}&prompt=login&code_challenge={codeChallenge}&code_challenge_method=S256",
			UseShellExecute = true
		});

		await SimpleListenerExample(prefixes);
	}

	static async Task redirectToLoginConfidential(string codeChallenge)
	{
		string[] prefixes =
		{
			Global.CallbackURL.TrimEnd('/') + "/"
		};

		System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
		{
			FileName = $"https://developer.api.autodesk.com/authentication/v2/authorize?response_type=code&client_id={Global.ClientId}&redirect_uri={HttpUtility.UrlEncode(Global.CallbackURL)}&scope={Global.Scopes}&prompt=login&code_challenge={codeChallenge}&code_challenge_method=S256",
			UseShellExecute = true
		});

		await SimpleListenerConfidentialExample(prefixes);
	}

	static async Task SimpleListenerExample(string[] prefixes)
	{
		if (!HttpListener.IsSupported)
		{
			throw new NotSupportedException("HttpListener is not supported in this context!");
		}
		if (prefixes == null || prefixes.Length == 0)
			throw new ArgumentException("prefixes");

		var listener = new HttpListener();
		foreach (string s in prefixes)
		{
			listener.Prefixes.Add(s);
		}
		listener.Start();

		HttpListenerContext context = listener.GetContext();
		HttpListenerRequest request = context.Request;
		HttpListenerResponse response = context.Response;

		string errorMessage = null;
		try
		{
			var queryParams = HttpUtility.ParseQueryString(request.Url.Query);
			string authCode = queryParams["code"];
			if (string.IsNullOrEmpty(authCode))
			{
				errorMessage = $"No auth code in callback. Query: {request.Url.Query}";
			}
			else
			{
				await GetPKCEToken(authCode);
				if (string.IsNullOrEmpty(Global.AccessToken))
				{
					errorMessage = "Token exchange failed - no access token received";
				}
			}
		}
		catch (Exception ex)
		{
			errorMessage = $"Error: {ex.Message}";
		}

		string responseString = errorMessage != null
			? $"<HTML><BODY>Error: {errorMessage}</BODY></HTML>"
			: "<HTML><BODY>Authentication successful! You can close this window.</BODY></HTML>";
		byte[] buffer = Encoding.UTF8.GetBytes(responseString);
		response.ContentLength64 = buffer.Length;
		response.OutputStream.Write(buffer, 0, buffer.Length);
		response.OutputStream.Close();
		listener.Stop();
	}

	static async Task SimpleListenerConfidentialExample(string[] prefixes)
	{
		if (!HttpListener.IsSupported)
		{
			throw new NotSupportedException("HttpListener is not supported in this context!");
		}
		if (prefixes == null || prefixes.Length == 0)
			throw new ArgumentException("prefixes");

		var listener = new HttpListener();
		foreach (string s in prefixes)
		{
			listener.Prefixes.Add(s);
		}
		listener.Start();

		HttpListenerContext context = listener.GetContext();
		HttpListenerRequest request = context.Request;
		HttpListenerResponse response = context.Response;

		string errorMessage = null;
		try
		{
			var queryParams = HttpUtility.ParseQueryString(request.Url.Query);
			string authCode = queryParams["code"];
			if (string.IsNullOrEmpty(authCode))
			{
				errorMessage = $"No auth code in callback. Query: {request.Url.Query}";
			}
			else
			{
				await GetPKCETokenConfidential(authCode);
				if (string.IsNullOrEmpty(Global.AccessToken))
				{
					errorMessage = "Token exchange failed - no access token received";
				}
			}
		}
		catch (Exception ex)
		{
			errorMessage = $"Error: {ex.Message}";
		}

		string responseString = errorMessage != null
			? $"<HTML><BODY>Error: {errorMessage}</BODY></HTML>"
			: "<HTML><BODY>Authentication successful! You can close this window.</BODY></HTML>";
		byte[] buffer = Encoding.UTF8.GetBytes(responseString);
		response.ContentLength64 = buffer.Length;
		response.OutputStream.Write(buffer, 0, buffer.Length);
		response.OutputStream.Close();
		listener.Stop();
	}

	static string RandomString(int length)
	{
		const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		return new string(Enumerable.Repeat(chars, length)
				.Select(s => s[Global.random.Next(s.Length)]).ToArray());

		//Note: The use of the Random class makes this unsuitable for anything security related, such as creating passwords or tokens.Use the RNGCryptoServiceProvider class if you need a strong random number generator
	}

	static string GenerateCodeChallenge(string codeVerifier)
	{
		var sha256 = SHA256.Create();
		var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
		var b64Hash = Convert.ToBase64String(hash);
		var code = Regex.Replace(b64Hash, "\\+", "-");
		code = Regex.Replace(code, "\\/", "_");
		code = Regex.Replace(code, "=+$", "");
		return code;
	}

	static async Task GetPKCEToken(string authCode)
	{
		var client = new HttpClient();
		var tokenParams = new Dictionary<string, string>
		{
			{ "client_id", Global.ClientId },
			{ "code_verifier", Global.codeVerifier },
			{ "code", authCode },
			{ "scope", Global.Scopes },
			{ "grant_type", "authorization_code" },
			{ "redirect_uri", Global.CallbackURL }
		};

		var request = new HttpRequestMessage
		{
			Method = HttpMethod.Post,
			RequestUri = new Uri("https://developer.api.autodesk.com/authentication/v2/token"),
			Content = new FormUrlEncodedContent(tokenParams),
		};

		using var response = await client.SendAsync(request);
		string bodystring = await response.Content.ReadAsStringAsync();
		if (!response.IsSuccessStatusCode)
		{
			throw new Exception($"Token request failed: {response.StatusCode} - {bodystring}");
		}
		var bodyjson = JObject.Parse(bodystring);
		Global.AccessToken = bodyjson["access_token"]?.Value<string>();
		Global.RefreshToken = bodyjson["refresh_token"]?.Value<string>();
	}

	static async Task GetPKCETokenConfidential(string authCode)
	{
		var client = new HttpClient();
		var tokenParams = new Dictionary<string, string>
		{
			{ "client_id", Global.ClientId },
			{ "client_secret", Global.ClientSecret },
			{ "code_verifier", Global.codeVerifier },
			{ "code", authCode },
			{ "scope", Global.Scopes },
			{ "grant_type", "authorization_code" },
			{ "redirect_uri", Global.CallbackURL }
		};

		var request = new HttpRequestMessage
		{
			Method = HttpMethod.Post,
			RequestUri = new Uri("https://developer.api.autodesk.com/authentication/v2/token"),
			Content = new FormUrlEncodedContent(tokenParams),
		};

		using var response = await client.SendAsync(request);
		string bodystring = await response.Content.ReadAsStringAsync();
		if (!response.IsSuccessStatusCode)
		{
			throw new Exception($"Token request failed: {response.StatusCode} - {bodystring}");
		}
		var bodyjson = JObject.Parse(bodystring);
		Global.AccessToken = bodyjson["access_token"]?.Value<string>();
		Global.RefreshToken = bodyjson["refresh_token"]?.Value<string>();
	}
}