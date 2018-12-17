using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using BingAdsAuthentication.Models;
using BingAdsAuthentication.AppCode;
using System.Net.Http;
using Newtonsoft.Json;
using BingAdsAuthentication.Extensions;
using Microsoft.BingAds;
using System.IO;
using System.Configuration;
using Microsoft.Extensions.Configuration;
using Microsoft.BingAds.V12.CustomerManagement;
using System.ServiceModel;

namespace BingAdsAuthentication.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _config;
        private readonly string _state = Common.GetUniqueToken(10, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        private static AuthorizationData _authorizationData;
        private static ServiceClient<ICustomerManagementService> _customerManagementService;

        public HomeController(IConfiguration config)
        {
            _config = config;
        }

        [HttpGet]
        [ActionName("Index")]
        public IActionResult IndexGet()
        {
            return View();
        }

        [HttpPost]
        [ActionName("Index")]
        [ValidateAntiForgeryToken]
        public IActionResult IndexPost(Models.Authentication authentication)
        {
            authentication.State = _state;
            Uri codeUri = Common.GetCodeUri(authentication.ClientId, authentication.State, Url.Action("Redirect", "Home", null, HttpContext.Request.Scheme));
            TempData["State"] = authentication.State;
            TempData["ClientId"] = authentication.ClientId;
            return Redirect(codeUri.ToString());
        }

        [HttpGet]
        public IActionResult Redirect(string code, string state)
        {
            string clientId = TempData["ClientId"].ToString();
            string originalState = TempData["State"].ToString();

            if (state != originalState)
            {
                throw new UnauthorizedAccessException("State code returned is not the same as that provided");
            }

            Models.Authentication authentication = new Models.Authentication()
            {
                ClientId = clientId,
                State = state,
                Scope = "bingads.manage",
                Code = code,
                GrantType = "authorization_code",
                RedirectUri = Url.Action("Redirect", "Home", null, HttpContext.Request.Scheme).ToString()
            };

            return View("Code", authentication);
        }

        [HttpGet]
        [ActionName("Code")]
        public IActionResult CodeGet(Models.Authentication authentication)
        {
            return View(authentication);
        }

        [HttpPost]
        [ActionName("Code")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CodePost(Models.Authentication authentication)
        {
            string tokenUri = "https://login.live.com/oauth20_token.srf";

            using (HttpClient client = new HttpClient())
            {
                FormUrlEncodedContent content = new FormUrlEncodedContent(authentication.ToKeyValue());
                HttpResponseMessage response = await client.PostAsync(tokenUri, content);

                Token token = JsonConvert.DeserializeObject<Token>(await response.Content.ReadAsStringAsync());
                TempData["ClientId"] = authentication.ClientId;
                TempData["ClientSecret"] = authentication.ClientSecret;
                return View("Token", token);
            }
        }

        [HttpGet]
        [ActionName("Token")]
        public IActionResult TokenGet(Token token)
        {
            return View(token);
        }

        [HttpPost]
        [ActionName("Account")]
        public IActionResult AccountPost(Token token)
        {
            AdvertiserAccount account = new AdvertiserAccount();

            try
            {
                Microsoft.BingAds.Authentication authentication = AuthenticateWithOAuth(token);

                // Most Bing Ads service operations require account and customer ID. 
                // This utiltiy operation sets the global authorization data instance 
                // to the first account that the current authenticated user can access. 
                IList<AdvertiserAccount> accounts = SetAuthorizationDataAsync(authentication, token.DeveloperToken).Result;
                account = accounts[0];

                // You can extend the console app with the examples library at:
                // https://github.com/BingAds/BingAds-dotNet-SDK/tree/master/examples/BingAdsExamples
            }
            // Catch authentication exceptions
            catch (OAuthTokenRequestException ex)
            {
                OutputStatusMessage(string.Format("OAuthTokenRequestException Message:\n{0}", ex.Message));
                if (ex.Details != null)
                {
                    OutputStatusMessage(string.Format("OAuthTokenRequestException Details:\nError: {0}\nDescription: {1}",
                    ex.Details.Error, ex.Details.Description));
                }
            }
            // Catch Customer Management service exceptions
            catch (FaultException<AdApiFaultDetail> ex)
            {
                OutputStatusMessage(string.Join("; ", ex.Detail.Errors.Select(error =>
                {
                    if ((error.Code == 105) || (error.Code == 106))
                    {
                        return "Authorization data is missing or incomplete for the specified environment.\n" +
                               "To run the examples switch users or contact support for help with the following error.\n";
                    }
                    return string.Format("{0}: {1}", error.Code, error.Message);
                })));
                OutputStatusMessage(string.Join("; ",
                    ex.Detail.Errors.Select(error => string.Format("{0}: {1}", error.Code, error.Message))));
            }
            catch (FaultException<Microsoft.BingAds.V12.CustomerManagement.ApiFault> ex)
            {
                OutputStatusMessage(string.Join("; ",
                    ex.Detail.OperationErrors.Select(error => string.Format("{0}: {1}", error.Code, error.Message))));
            }
            catch (HttpRequestException ex)
            {
                OutputStatusMessage(ex.Message);
            }

            return View(account);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        /// <summary>
        /// Authenticates the current user via OAuth.
        /// </summary>
        /// <returns>The OAuth authentication instance for a user.</returns>
        private Microsoft.BingAds.Authentication AuthenticateWithOAuth(Token token)
        {
            var apiEnvironment =
                ConfigurationManager.AppSettings["BingAdsEnvironment"] == ApiEnvironment.Sandbox.ToString() ?
                ApiEnvironment.Sandbox : ApiEnvironment.Production;

            string clientId = TempData["ClientId"].ToString();
            string clientSecret = TempData["ClientSecret"].ToString();

            var oAuthWebAuthCodeGrant = new OAuthWebAuthCodeGrant(
                clientId,
                clientSecret,
                new Uri(Url.Action("Redirect", "Home", null, HttpContext.Request.Scheme).ToString()),
                apiEnvironment);

            // It is recommended that you specify a non guessable 'state' request parameter to help prevent
            // cross site request forgery (CSRF). 
            oAuthWebAuthCodeGrant.State = _state;

            string refreshToken = token.RefreshToken;

            AuthorizeWithRefreshTokenAsync(oAuthWebAuthCodeGrant, refreshToken).Wait();

            return oAuthWebAuthCodeGrant;
        }

        /// <summary>
        /// Requests new access and refresh tokens given an existing refresh token.
        /// </summary>
        /// <param name="authentication">The OAuth authentication instance for a user.</param>
        /// <param name="refreshToken">The previous refresh token.</param>
        /// <returns></returns>
        private static Task<OAuthTokens> AuthorizeWithRefreshTokenAsync(
            OAuthWebAuthCodeGrant authentication,
            string refreshToken)
        {
            return authentication.RequestAccessAndRefreshTokensAsync(refreshToken);
        }

        /// <summary>
        /// Utility method for setting the customer and account identifiers within the global 
        /// <see cref="_authorizationData"/> instance. 
        /// </summary>
        /// <param name="authentication">The OAuth authentication credentials.</param>
        /// <returns></returns>
        private async Task<IList<AdvertiserAccount>> SetAuthorizationDataAsync(Microsoft.BingAds.Authentication authentication, string developerToken)
        {
            _authorizationData = new AuthorizationData
            {
                Authentication = authentication,
                DeveloperToken = developerToken
            };

            _customerManagementService = new ServiceClient<ICustomerManagementService>(_authorizationData);

            var getUserRequest = new GetUserRequest
            {
                UserId = null
            };

            var getUserResponse = (await _customerManagementService.CallAsync((s, r) => s.GetUserAsync(r), getUserRequest));
            var user = getUserResponse.User;

            var predicate = new Predicate
            {
                Field = "UserId",
                Operator = PredicateOperator.Equals,
                Value = user.Id.ToString()
            };

            var paging = new Paging
            {
                Index = 0,
                Size = 10
            };

            var searchAccountsRequest = new SearchAccountsRequest
            {
                Ordering = null,
                PageInfo = paging,
                Predicates = new[] { predicate }
            };

            var searchAccountsResponse =
                (await _customerManagementService.CallAsync((s, r) => s.SearchAccountsAsync(r), searchAccountsRequest));

            var accounts = searchAccountsResponse.Accounts.ToArray();
            //if (accounts.Length <= 0) return;

            _authorizationData.AccountId = (long)accounts[0].Id;
            _authorizationData.CustomerId = (int)accounts[0].ParentCustomerId;

            //OutputArrayOfAdvertiserAccount(accounts);

            return accounts;
        }

        /// <summary>
        /// Returns the prior refresh token if available.
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns>The latest stored refresh token.</returns>
        private static bool GetRefreshToken(out string refreshToken)
        {
            var filePath = Environment.CurrentDirectory + @"\Data\refreshtoken.txt";
            if (!System.IO.File.Exists(filePath))
            {
                refreshToken = null;
                return false;
            }
            
            String fileContents;
            using (StreamReader sr = new StreamReader(filePath))
            {
                fileContents = sr.ReadToEnd();
            }

            if (string.IsNullOrEmpty(fileContents))
            {
                refreshToken = null;
                return false;
            }

            try
            {
                refreshToken = fileContents;
                return true;
            }
            catch (FormatException)
            {
                refreshToken = null;
                return false;
            }
        }

        #region OutputHelpers

        /**
         * You can extend the console app with the example helpers at:
         * https://github.com/BingAds/BingAds-dotNet-SDK/tree/master/examples/BingAdsExamples
         **/

        private static void OutputArrayOfAdvertiserAccount(IList<AdvertiserAccount> dataObjects)
        {
            if (null != dataObjects)
            {
                foreach (var dataObject in dataObjects)
                {
                    OutputAdvertiserAccount(dataObject);
                    OutputStatusMessage("\n");
                }
            }
        }

        private static void OutputAdvertiserAccount(AdvertiserAccount dataObject)
        {
            if (null != dataObject)
            {
                OutputStatusMessage(string.Format("BillToCustomerId: {0}", dataObject.BillToCustomerId));
                OutputStatusMessage(string.Format("CurrencyCode: {0}", dataObject.CurrencyCode));
                OutputStatusMessage(string.Format("AccountFinancialStatus: {0}", dataObject.AccountFinancialStatus));
                OutputStatusMessage(string.Format("Id: {0}", dataObject.Id));
                OutputStatusMessage(string.Format("Language: {0}", dataObject.Language));
                OutputStatusMessage(string.Format("LastModifiedByUserId: {0}", dataObject.LastModifiedByUserId));
                OutputStatusMessage(string.Format("LastModifiedTime: {0}", dataObject.LastModifiedTime));
                OutputStatusMessage(string.Format("Name: {0}", dataObject.Name));
                OutputStatusMessage(string.Format("Number: {0}", dataObject.Number));
                OutputStatusMessage(string.Format("ParentCustomerId: {0}", dataObject.ParentCustomerId));
                OutputStatusMessage(string.Format("PaymentMethodId: {0}", dataObject.PaymentMethodId));
                OutputStatusMessage(string.Format("PaymentMethodType: {0}", dataObject.PaymentMethodType));
                OutputStatusMessage(string.Format("PrimaryUserId: {0}", dataObject.PrimaryUserId));
                OutputStatusMessage(string.Format("AccountLifeCycleStatus: {0}", dataObject.AccountLifeCycleStatus));
                OutputStatusMessage(string.Format("TimeStamp: {0}", dataObject.TimeStamp));
                OutputStatusMessage(string.Format("TimeZone: {0}", dataObject.TimeZone));
                OutputStatusMessage(string.Format("PauseReason: {0}", dataObject.PauseReason));
                OutputArrayOfKeyValuePairOfstringstring(dataObject.ForwardCompatibilityMap);
                OutputArrayOfCustomerInfo(dataObject.LinkedAgencies);
                OutputStatusMessage(string.Format("SalesHouseCustomerId: {0}", dataObject.SalesHouseCustomerId));
                OutputArrayOfKeyValuePairOfstringstring(dataObject.TaxInformation);
                OutputStatusMessage(string.Format("BackUpPaymentInstrumentId: {0}", dataObject.BackUpPaymentInstrumentId));
                OutputStatusMessage(string.Format("BillingThresholdAmount: {0}", dataObject.BillingThresholdAmount));
                OutputAddress(dataObject.BusinessAddress);
                OutputStatusMessage(string.Format("AutoTagType: {0}", dataObject.AutoTagType));
                OutputStatusMessage(string.Format("SoldToPaymentInstrumentId: {0}", dataObject.SoldToPaymentInstrumentId));
            }
        }

        private static void OutputAddress(Address dataObject)
        {
            if (null != dataObject)
            {
                OutputStatusMessage(string.Format("City: {0}", dataObject.City));
                OutputStatusMessage(string.Format("CountryCode: {0}", dataObject.CountryCode));
                OutputStatusMessage(string.Format("Id: {0}", dataObject.Id));
                OutputStatusMessage(string.Format("Line1: {0}", dataObject.Line1));
                OutputStatusMessage(string.Format("Line2: {0}", dataObject.Line2));
                OutputStatusMessage(string.Format("Line3: {0}", dataObject.Line3));
                OutputStatusMessage(string.Format("Line4: {0}", dataObject.Line4));
                OutputStatusMessage(string.Format("PostalCode: {0}", dataObject.PostalCode));
                OutputStatusMessage(string.Format("StateOrProvince: {0}", dataObject.StateOrProvince));
                OutputStatusMessage(string.Format("TimeStamp: {0}", dataObject.TimeStamp));
                OutputStatusMessage(string.Format("BusinessName: {0}", dataObject.BusinessName));
            }
        }

        private static void OutputArrayOfKeyValuePairOfstringstring(IList<KeyValuePair<string, string>> dataObjects)
        {
            if (null != dataObjects)
            {
                foreach (var dataObject in dataObjects)
                {
                    OutputKeyValuePairOfstringstring(dataObject);
                }
            }
        }

        private static void OutputKeyValuePairOfstringstring(KeyValuePair<string, string> dataObject)
        {
            if (null != dataObject.Key)
            {
                OutputStatusMessage(string.Format("key: {0}", dataObject.Key));
                OutputStatusMessage(string.Format("value: {0}", dataObject.Value));
            }
        }

        private static void OutputCustomerInfo(CustomerInfo dataObject)
        {
            if (null != dataObject)
            {
                OutputStatusMessage(string.Format("Id: {0}", dataObject.Id));
                OutputStatusMessage(string.Format("Name: {0}", dataObject.Name));
            }
        }

        private static void OutputArrayOfCustomerInfo(IList<CustomerInfo> dataObjects)
        {
            if (null != dataObjects)
            {
                foreach (var dataObject in dataObjects)
                {
                    OutputCustomerInfo(dataObject);
                    OutputStatusMessage("\n");
                }
            }
        }

        private static void OutputStatusMessage(String msg)
        {
            Console.WriteLine(msg);
        }

        #endregion OutputHelpers
    }
}
