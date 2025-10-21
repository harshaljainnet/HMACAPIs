using System.Security.Cryptography;
using System.Text;

namespace HMACAPIs
{
    public class HmacValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _secretKey;

        public HmacValidationMiddleware(RequestDelegate next, string secretKey)
        {
            _next = next;
            _secretKey = secretKey;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue("x-date", out var dateHeader) ||
                !context.Request.Headers.TryGetValue("x-signature", out var signatureHeader))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("{\"error\":\"Missing x-date or x-signature headers\"}");
                return;
            }

            string path = context.Request.Path;

            // Extract and sort query parameters
            var queryParams = context.Request.Query;
            var sortedQuery = string.Join("&", queryParams.Keys.OrderBy(k => k)
                                                   .Select(k => $"{k}={queryParams[k]}"));

            // Build string to sign
            string stringToSign = $"{context.Request.Method}\n{path}\n{sortedQuery}\n{dateHeader}";

            // Compute HMAC
            byte[] keyBytes = Encoding.UTF8.GetBytes(_secretKey);
            byte[] messageBytes = Encoding.UTF8.GetBytes(stringToSign);

            using var hmac = new HMACSHA256(keyBytes);
            byte[] hash = hmac.ComputeHash(messageBytes);
            string computedSignature = Convert.ToBase64String(hash);

            // Logging for debugging
            Console.WriteLine("----- HMAC Debug -----"); 
            Console.WriteLine("Received x-date: " + dateHeader); 
            Console.WriteLine("Received x-signature: " + signatureHeader); 
            Console.WriteLine("Computed string to sign: " + computedSignature);

            if (computedSignature != signatureHeader)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("{\"error\":\"Invalid HMAC signature\"}");
                return;
            }

            await _next(context);
        }
    }
}
