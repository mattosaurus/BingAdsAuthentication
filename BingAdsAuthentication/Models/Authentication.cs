using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;

namespace BingAdsAuthentication.Models
{
    public class Authentication
    {
        [DisplayName("Client ID")]
        [JsonProperty("client_id")]
        public string ClientId { get; set; }

        [DisplayName("Client Secret")]
        [JsonProperty("client_secret")]
        public string ClientSecret { get; set; }

        [JsonProperty("state")]
        public string State { get; set; }

        [JsonProperty("code")]
        public string Code { get; set; }

        [JsonProperty("scope")]
        public string Scope { get; set; }

        [JsonProperty("grant_type")]
        public string GrantType { get; set; }

        [JsonProperty("redirect_uri")]
        public string RedirectUri { get; set; }
    }
}
