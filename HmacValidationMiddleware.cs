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

            // Build string to sign: METHOD + PATH + DATE
            string stringToSign = $"{context.Request.Method}\n{context.Request.Path}\n{dateHeader}";

            // Compute HMAC using secret key
            byte[] keyBytes = Encoding.UTF8.GetBytes(_secretKey);
            byte[] messageBytes = Encoding.UTF8.GetBytes(stringToSign);

            using var hmac = new HMACSHA256(keyBytes);
            byte[] hash = hmac.ComputeHash(messageBytes);
            string computedSignature = Convert.ToBase64String(hash);

            // Compare signatures
            if (computedSignature != signatureHeader)
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("{\"error\":\"Invalid HMAC signature\"}");
                return;
            }

            // Signature valid — continue
            await _next(context);
        }
    }
}
