using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace AdfsKeycloakMfa
{
    /// <summary>
    /// AD FS MFA adapter that redirects to Keycloak OIDC for 2FA.
    /// </summary>
    public class KeycloakMfaAdapter : IAuthenticationAdapter
    {
        // Configuration for Keycloak (injected via AD FS config)
        private static string KeycloakAuthority;   // e.g. "https://keycloak.example.com/realms/myrealm"
        private static string ClientId;
        private static string ClientSecret;
        private static string RedirectUri;         // e.g. "https://adfs-server/adfs/ls/auth"
        
        // Metadata property: AD FS will call this to get adapter metadata.
        public IAuthenticationAdapterMetadata Metadata { 
            get { return new KeycloakMfaAdapterMetadata(); } 
        }

        // Called once when AD FS loads the adapter; we can read config here.
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            // AD FS passes a configuration file path if used at Register time.
            // Read JSON config if present (e.g. {"authority":"...","clientId":"...","clientSecret":"...", "redirectUri":"..."}).
            if (configData != null && configData.ConfigurationFilePath != null)
            {
                // Read and parse JSON from configData.ConfigurationFilePath
                var cfgJson = System.IO.File.ReadAllText(configData.ConfigurationFilePath);
                dynamic cfg = System.Text.Json.JsonDocument.Parse(cfgJson).RootElement;

                KeycloakAuthority = cfg.GetProperty("authority").GetString().TrimEnd('/');
                ClientId          = cfg.GetProperty("clientId").GetString();
                ClientSecret      = cfg.GetProperty("clientSecret").GetString();
                RedirectUri       = cfg.GetProperty("redirectUri").GetString();
            }
        }

        public void OnAuthenticationPipelineUnload() { }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            // Optionally check the user or context to decide if MFA should apply.
            return true;
        }

        /// <summary>
        /// BeginAuthentication is called when AD FS first presents the MFA UI.
        /// We return a form that immediately redirects to Keycloak's /authorize endpoint.
        /// </summary>
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request, IAuthenticationContext authContext)
        {
            // Render HTML that auto-redirects to Keycloak with the authorization request.
            // We include the required AD FS hidden fields (AuthMethod, Context), and our own state/nonce if needed.
            string html = $@"
<!DOCTYPE html>
<html><body>
<form id='loginForm' method='post'>
  <input type='hidden' name='AuthMethod' value='%AuthMethod%'/>
  <input type='hidden' name='Context' value='%Context%'/>
  <!-- Additional hidden fields to capture code and state from callback -->
  <input type='hidden' name='code' id='codeHidden'/>
  <input type='hidden' name='state' id='stateHidden'/>
</form>
<script>
// Generate random state and nonce for OIDC (in practice, store nonce to verify later)
var state = Math.random().toString(36).substring(2);
document.getElementById('stateHidden').value = state;

// Construct Keycloak authorization URL
var authUrl = '{KeycloakAuthority}/protocol/openid-connect/auth'
    + '?response_type=code'
    + '&client_id={ClientId}'
    + '&redirect_uri=' + encodeURIComponent('{RedirectUri}')
    + '&state=' + encodeURIComponent(state)
    + '&scope=openid';

// Redirect the browser
window.location = authUrl;
</script>
</body></html>";
            return new AdapterPresentation(html);
        }

        /// <summary>
        /// OnError is called if an exception was thrown. We return an error page.
        /// </summary>
        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            string message = WebUtility.HtmlEncode(ex.Message);
            string html = $"<html><body><h3>Authentication error: {message}</h3></body></html>";
            return new AdapterPresentation(html);
        }

        /// <summary>
        /// TryEndAuthentication is called on form POST. We look for the 'code' field posted by our form.
        /// If present, we exchange it for an ID token and validate it.
        /// </summary>
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData, HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            outgoingClaims = Array.Empty<Claim>();

            // Check if the Keycloak redirect gave us a code parameter
            if (proofData?.Properties != null && proofData.Properties.ContainsKey("code"))
            {
                string code = proofData.Properties["code"] as string;
                string stateReturned = proofData.Properties.ContainsKey("state") ? proofData.Properties["state"] as string : null;
                try
                {
                    // Exchange code for tokens at Keycloak token endpoint
                    var tokenResponse = ExchangeCodeForTokenAsync(code).GetAwaiter().GetResult();
                    // Validate ID token signature and claims
                    var userClaims = ValidateIdToken(tokenResponse.IdToken, stateReturned);

                    // Success: add authentication method claim and return null to finish
                    outgoingClaims = new[]
                    {
                        // This value should match one of the AuthenticationMethods in metadata
                        new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                                  "urn:example:auth:KeycloakOIDC")
                    };
                    return null;
                }
                catch (Exception ex)
                {
                    // Token exchange or validation failed: show error
                    return OnError(request, new ExternalAuthenticationException($"2FA failed: {ex.Message}", authContext));
                }
            }

            // No code: authentication not complete. Show an error or redisplay (unlikely path).
            return OnError(request, new ExternalAuthenticationException("No code returned from Keycloak", authContext));
        }

        /// <summary>
        /// Calls Keycloak token endpoint to exchange authorization code for tokens (ID token).
        /// </summary>
        private async Task<OidcTokenResponse> ExchangeCodeForTokenAsync(string code)
        {
            using (var http = new HttpClient())
            {
                var req = new HttpRequestMessage(HttpMethod.Post, $"{KeycloakAuthority}/protocol/openid-connect/token");
                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string,string>("grant_type",    "authorization_code"),
                    new KeyValuePair<string,string>("code",          code),
                    new KeyValuePair<string,string>("client_id",     ClientId),
                    new KeyValuePair<string,string>("client_secret", ClientSecret),
                    new KeyValuePair<string,string>("redirect_uri",  RedirectUri)
                });
                req.Content = content;
                HttpResponseMessage resp = await http.SendAsync(req).ConfigureAwait(false);
                resp.EnsureSuccessStatusCode();
                string json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = System.Text.Json.JsonDocument.Parse(json);
                return new OidcTokenResponse
                {
                    IdToken = doc.RootElement.GetProperty("id_token").GetString()
                };
            }
        }

        /// <summary>
        /// Validates the ID token using Keycloak’s JWKS. Checks signature, issuer, audience, expiry, etc.
        /// Throws if invalid. Returns claims if valid.
        /// </summary>
        private ClaimsIdentity ValidateIdToken(string idToken, string state)
        {
            // Use OIDC configuration to get issuer, JWKS URI
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"{KeycloakAuthority}/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever());
            OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;

            // Validate token signature and claims
            TokenValidationParameters tvp = new TokenValidationParameters
            {
                ValidIssuer = config.Issuer,
                ValidAudience = ClientId,
                IssuerSigningKeys = config.SigningKeys,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ValidateIssuer = true,
                ValidateAudience = true
            };
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            SecurityToken validated;
            var principal = handler.ValidateToken(idToken, tvp, out validated);

            // OPTIONAL: Check nonce if used (not implemented here; should compare with stored nonce)
            // SecurityToken jwt = validated;
            // string nonce = principal.FindFirst("nonce")?.Value; // compare to state if used

            return (ClaimsIdentity)principal.Identity;
        }
    }

    /// <summary>
    /// Metadata for the adapter: names, claims, etc.
    /// </summary>
    public class KeycloakMfaAdapterMetadata : IAuthenticationAdapterMetadata
    {
        public string[] AuthenticationMethods {
            get {
                // The authentication method URI must match what TryEndAuthentication returns in the Claim above
                return new[] { "urn:example:auth:KeycloakOIDC" };
            }
        }
        public Dictionary<int, string> FriendlyNames {
            get {
                // Display name on MFA choice page
                return new Dictionary<int, string> {
                    { new System.Globalization.CultureInfo("en").LCID, "Keycloak OIDC 2FA" }
                };
            }
        }
        public Dictionary<int, string> Descriptions {
            get {
                return new Dictionary<int, string> {
                    { new System.Globalization.CultureInfo("en").LCID, "Use Keycloak for second-factor authentication" }
                };
            }
        }
        public string[] IdentityClaims {
            get {
                // Our adapter requires the AD FS user identity (e.g. UPN) in the context
                return new[] { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn" };
            }
        }
        public bool RequiresIdentity {
            get { return true; }
        }
        public string AdminName {
            get { return "Keycloak OIDC MFA Adapter"; }
        }
        public int[] AvailableLcids {
            get { return new[] { new System.Globalization.CultureInfo("en").LCID }; }
        }
    }

    /// <summary>
    /// Simple holder for token response fields we care about.
    /// </summary>
    public class OidcTokenResponse
    {
        public string IdToken { get; set; }
    }

    /// <summary>
    /// Helper class to render HTML as IAdapterPresentation.
    /// </summary>
    public class AdapterPresentation : IAdapterPresentationForm
    {
        private readonly string _html;
        public AdapterPresentation(string html) { _html = html; }

        public string GetFormHtml(int lcid) => _html;
        public string GetPageTitle(int lcid) => "Keycloak 2FA";
        public string GetFormPreRenderHtml(int lcid) => null;
    }
}