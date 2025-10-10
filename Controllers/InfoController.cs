using Microsoft.AspNetCore.Mvc;

namespace HMACAPIs.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class InfoController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetInfo()
        {
            return Ok(new
            {
                Id = 1,
                Name = "HMAC Protected API",
                Description = "This info requires a valid HMAC signature"
            });
        }
    }
}
