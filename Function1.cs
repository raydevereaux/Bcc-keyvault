using System;
using System.IO;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;

namespace Bcc_KeyVault
{
    public static class Credentials 
    {
        [FunctionName("Credentials")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = "Credentials/{myVersion}/{myFunction}/{myMethod}/{senderId}")] HttpRequest req,
            ILogger log, string myVersion, string myFunction, string myMethod, string senderId)
        {
            string vaultBaseUrl = System.Environment.GetEnvironmentVariable("VaultBaseUrl", EnvironmentVariableTarget.Process);
            string bccAccessKey = req.Headers["bcc-access-key"];
            string build = "07/11/2019 14.43.00.829";

            ObjectResult resp;
            string mode = System.Environment.GetEnvironmentVariable("Mode", EnvironmentVariableTarget.Process);

            try
            {
                string vaultUrl = vaultBaseUrl + @"/" + myFunction + @"/" + bccAccessKey;  // +@"/ca85077d61a9444c83b55e49ef6224b5";
                KeyVaultModel keyVault = new KeyVaultModel();
                string functionKey = await keyVault.OnGetAsync(vaultUrl);  //"iKaokUrfUCkcmAFuIxRfvgDnVDhDm6MWwJzV9H9j76dcdQSD4qzSwQ==";  // await keyVault.OnGetAsync(vaultUrl);
                switch (myVersion.ToLower())
                {
                    case "v0":
                        AuthTokenV00 auth00 = await geVer00Token(build, myFunction, myMethod, mode, senderId, functionKey);
                        resp = new OkObjectResult(auth00);
                        break;
                    default:
                        AuthTokenV01 auth = await geVer01Token(build, functionKey);
                        resp = new OkObjectResult(auth);
                        break;
                }
            }
            catch (Exception e)
            {
                ErrorToken errObj = new ErrorToken();
                errObj.build = build;
                errObj.status = 404;
                errObj.functionName = myFunction;
                errObj.message = e.Message;
                resp = new NotFoundObjectResult(errObj);
            }

            return resp;
        }

        private static async Task<AuthTokenV00> geVer00Token(string build, string myFunction, string myMethod, string mode, string senderId, string functionKey)
        {
            AuthTokenV00 auth = new AuthTokenV00();
            auth.build = build;
            auth.header.Add("Content-Type", "text/plain");
            auth.header.Add("x-functions-key", functionKey);  // "iKaokUrfUCkcmAFuIxRfvgDnVDhDm6MWwJzV9H9j76dcdQSD4qzSwQ==");
            auth.url = "https://" + myFunction + ".azurewebsites.net/api/" + myMethod + "/" + mode + "/" + senderId + "/121/csv";

            return auth;
        }
        private static async Task<AuthTokenV01> geVer01Token(string build, string functionKey)
        {
            AuthTokenV01 auth = new AuthTokenV01();
            auth.build = build;
            auth.header.Add("Content-Type", "text/plain");
            auth.header.Add("x-functions-key", functionKey);  //"iKaokUrfUCkcmAFuIxRfvgDnVDhDm6MWwJzV9H9j76dcdQSD4qzSwQ==");

            return auth;
        }
    }

    public class AuthTokenV00
    {
        public string build = "";
        private static DateTime dateTime = DateTime.Now;
        public int status = 0;
        public Dictionary<string, string> header = new Dictionary<string, string>();
        public string url = "";
        public string message = "";
        public string timestamp = dateTime.ToString("MM/dd/yyyy HH.mm.ss.fff");


    }

    public class AuthTokenV01
    {
        public string build = "";
        public int status = 0;
        public Dictionary<string, string> header = new Dictionary<string, string>();
    }
    public class ErrorToken
    {

        public string build = "";
        public int status = 0;
        private static DateTime dateTime = DateTime.Now;
        public string functionName = "";
        public string message = "";
        public string timestamp = dateTime.ToString("MM/dd/yyyy HH.mm.ss.fff");

    }

    public class KeyVaultModel
    {
        //public string vaultUrl = "https://bc-keyvault-dev.vault.azure.net/secrets/bccalc/ca85077d61a9444c83b55e49ef6224b5";
        //public static string Message { get; set; }

        public static async Task execute(string url)
        {
            KeyVaultModel mod = new KeyVaultModel();
            string msg = await mod.OnGetAsync(url);
        }

        public async Task<string> OnGetAsync(string vaultUrl)
        {
            string accessKey = "";
            int retries = 0;
            bool retry = false;

            AzureServiceTokenProvider azureServiceTokenProvider = new AzureServiceTokenProvider();
            KeyVaultClient keyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback));
            var secret = await keyVaultClient.GetSecretAsync(vaultUrl).ConfigureAwait(false);
            accessKey = secret.Value;

            return accessKey;
        }

        // This method implements exponential backoff if there are 429 errors from Azure Key Vault
        private static long getWaitTime(int retryCount)
        {
            long waitTime = ((long)Math.Pow(2, retryCount) * 100L);
            return waitTime;
        }

        // This method fetches a token from Azure Active Directory, which can then be provided to Azure Key Vault to authenticate
        public async Task<string> GetAccessTokenAsync()
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            string accessToken = await azureServiceTokenProvider.GetAccessTokenAsync("https://vault.azure.net");
            return accessToken;
        }
    }

}
