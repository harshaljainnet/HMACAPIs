using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace HMACAPIs.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class EmployeeController : ControllerBase
    {
        // Sample in-memory data
        private static readonly Dictionary<int, string> Employees = new()
        {
            { 1, "Neil" },
            { 2, "Mac" },
            { 3, "Alice" },
            { 4, "Bob" }
        };

        //        [AllowAnonymous]
        // GET /Employee/GetEmployee/{employeeId}
        [HttpGet("GetEmployee")]
        public IActionResult GetEmployee([FromQuery] int employeeId)
        {
            if (Employees.TryGetValue(employeeId, out var employeeName))
            {
                return Ok(new { Id = employeeId, Name = employeeName });
            }
            else
            {
                return NotFound(new { Error = $"Employee with Id {employeeId} not found" });
            }
        }
    }
}
