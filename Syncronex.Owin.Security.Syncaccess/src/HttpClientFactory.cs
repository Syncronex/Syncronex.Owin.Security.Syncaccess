using System;
using System.Net.Http;

namespace Syncronex.Owin.Security.Syncaccess
{
    /// <summary>
    /// Manages our Http connection to the oAuth server
    /// </summary>
    internal class HttpClientFactory
    {
        private const int DefaultTimeoutMiliseconds = 3000;

        private static HttpClient _httpClient;
        private readonly object _clientLock = new object();

        public HttpClient GetHttpClient()
        {
            return GetHttpClient(DefaultTimeoutMiliseconds);
        }

        public HttpClient GetHttpClient(int serverTimeout)
        {
            if (_httpClient == null)
            {
                lock (_clientLock)
                {
                    if (_httpClient == null)
                    {
                        var timeout = TimeSpan.FromMilliseconds(serverTimeout);

                        _httpClient = new HttpClient()
                        {
                            Timeout = timeout,
                            MaxResponseContentBufferSize = 1024 * 1024 * 10
                        };

                        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Syncronex Owin syncAccess middleware");
                        _httpClient.DefaultRequestHeaders.ExpectContinue = false;
                    }
                }
            }

            return _httpClient;
        }
    }
}