using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Syncronex.Owin.Security.Syncaccess
{
    public class AccessTokenManager
    {
        private readonly SyncaccessAuthenticationOptions _options;
        private readonly HttpClientFactory _httpClientFactory = new HttpClientFactory();
        
        public AccessTokenManager(SyncaccessAuthenticationOptions options)
        {
            _options = options;
        }

        public async Task<string> RefreshAccessToken(string refreshToken)
        {
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, _options.Endpoints.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(
                    Encoding.ASCII.GetBytes(
                        $"{_options.ClientId}:{_options.ClientSecret}")));

            requestMessage.Content = GetTokenRequestBody(refreshToken);
            var http = _httpClientFactory.GetHttpClient();
            var tokenResponse = await http.SendAsync(requestMessage);

            tokenResponse.EnsureSuccessStatusCode();

            var text = await tokenResponse.Content.ReadAsStringAsync();

            var response = JsonConvert.DeserializeObject<dynamic>(text);
            var accessToken = (string) response.access_token;

            return accessToken;
        }

        /// <summary>
        /// Get the POST body data for our call to token endpoint (to exchange authorization code
        /// for access token
        /// </summary>
        private FormUrlEncodedContent GetTokenRequestBody(string refreshToken)
        {
            var body = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("grant_type","refresh_token"),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("scope", _options.TenantId)

                //new KeyValuePair<string, string>("client_id", options.ClientId),
                //new KeyValuePair<string, string>("client_secret", options.ClientSecret)
            };

            return new FormUrlEncodedContent(body);
        }


    }
}