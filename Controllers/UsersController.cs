using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TestResComp3.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
//using NuGet.Protocol.Plugins;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace TestResComp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly TestResComp2Context _context;
        private readonly IConfiguration _configuration;

        public UsersController(TestResComp2Context context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // GET: api/Users
        [HttpGet("GetAllUsers")]
        [CustomAuthorize("Admin","Super Admin")] // You can add more roles if needed, e.g., [CustomAuthorize("Admin", "Manager")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers()
        {
          if (_context.Users == null)
          {
              return NotFound();
          }
            return await _context.Users.ToListAsync();
        }

        // GET: api/Users/5
        [HttpGet("GetUserById/{id}")]
        public async Task<ActionResult<User>> GetUser(int id)
        {
          if (_context.Users == null)
          {
              return NotFound();
          }
            var user = await _context.Users.FindAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            return user;
        }

        [HttpGet("GetUserId/{userName}")]
        public async Task<ActionResult<int>> GetUserId(string userName)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.UserName == userName);

            if (user == null)
            {
                return NotFound(); // Or return another appropriate response based on your requirements
            }

            return user.UserId;
        }

        //// PUT: api/Users/5
        //// To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        //[HttpPut("UpdateUserById/{id}")]
        //public async Task<IActionResult> PutUser(int id, User user)
        //{
        //    if (id != user.UserId)
        //    {
        //        return BadRequest();
        //    }

        //    _context.Entry(user).State = EntityState.Modified;

        //    try
        //    {
        //        await _context.SaveChangesAsync();
        //    }
        //    catch (DbUpdateConcurrencyException)
        //    {
        //        if (!UserExists(id))
        //        {
        //            return NotFound();
        //        }
        //        else
        //        {
        //            throw;
        //        }
        //    }

        //    return NoContent();
        //}


        [HttpPut("UpdateUserById/{id}")]
        public async Task<IActionResult> PutUser(int id, User updatedUser)
        {
            if (id==0)
            {
                return BadRequest();
            }

            // Retrieve the existing user from the database
            var existingUser = await _context.Users.FindAsync(id);

            if (existingUser == null)
            {
                return NotFound();
            }

            // Update only specific properties
            existingUser.UserName = updatedUser.UserName ?? existingUser.UserName;
            existingUser.FullName = updatedUser.FullName ?? existingUser.FullName;
            existingUser.Email = updatedUser.Email ?? existingUser.Email;
            existingUser.Mobile = updatedUser.Mobile ?? existingUser.Mobile;

            // Save the changes
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!UserExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return NoContent();
        }


        // POST: api/Users
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost("Register")]
        public async Task<ActionResult<User>> PostUser(User user)
        {
            try
            {
                if (_context.Users == null)
                {
                    return Problem("Entity set 'TestResComp1Context.Users' is null.");
                }

                // Hash the password before saving to the database
                user.PasswordHash = HashPassword(user.PasswordHash);

                // Add the user to the Users collection
                _context.Users.Add(user);

                // Assign a role to the user (assuming you have a role name in mind)
                Role userRole = new Role
                {
                    RoleName = "User", // Replace with the actual role name
                    User = user
                };
                _context.Roles.Add(userRole);

                // Save changes to the database
                await _context.SaveChangesAsync();

                return CreatedAtAction("GetUser", new { id = user.UserId }, user);
            }
            catch (DbUpdateException)
            {
                // Handle unique constraint violation or other specific exceptions if needed
                return Conflict();
            }
            catch (Exception ex)
            {
                // Handle other exceptions appropriately
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }



        // DELETE: api/Users/5
        [HttpDelete("Delete/{id}")]
        [CustomAuthorize("Super Admin")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            if (_context.Users == null)
            {
                return NotFound();
            }
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            return NoContent();
        }





        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            var userWithRole = await AuthenticateUserAsync(loginRequest.Username, loginRequest.Password);

            if (userWithRole != null)
            {
                var token = GenerateJwtToken(userWithRole);
                return Ok(token);
            }

            // Check if the username is valid but the password is incorrect
            var userExists = await CheckIfUsernameExists(loginRequest.Username);
            if (userExists)
            {
                return Unauthorized("Incorrect Password");
            }

            // If the username is not valid
            return Unauthorized("Incorrect UserName and Password");
        }

        private async Task<bool> CheckIfUsernameExists(string username)
        {
            // Implement your logic to check if the username exists in the database
            // For example, using Entity Framework Core:

            var user = await _context.Users.SingleOrDefaultAsync(u => u.UserName == username);
            return user != null;
        }


        private async Task<UserWithRoleDTO> AuthenticateUserAsync(string username, string password)
        {
            var storedUser = await _context.Users
                .FirstOrDefaultAsync(u => u.UserName == username);

            if (storedUser != null)
            {
                // Determine the length of the extra characters to remove
                int extraCharactersToRemove = 4;

                // Remove the last two characters from the stored password
                var storedPasswordWithoutExtraChars = password.Substring(0, password.Length - extraCharactersToRemove).ToUpper();

                // Write to the console for debugging
                Console.WriteLine("Stored Password Without Extra Chars: " + storedPasswordWithoutExtraChars);

                // Compare the modified stored password with the provided password
                if (storedUser.PasswordHash == storedPasswordWithoutExtraChars)
                {
                    // Fetch the role from RoleMgmt table based on UserId
                    var role = await _context.Roles
                        .Where(r => r.UserId == storedUser.UserId)
                        .FirstOrDefaultAsync();

                    // Create a DTO containing both user and role information
                    var userWithRole = new UserWithRoleDTO
                    {
                        UserId = storedUser.UserId,
                        UserName = storedUser.UserName,
                        Email = storedUser.Email,
                        RoleName = role?.RoleName // Check for null to avoid potential issues
                    };

                    return userWithRole;
                }
            }

            return null; // Authentication failed
        }

        private string GenerateJwtToken(UserWithRoleDTO user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim("Email", user.Email), // Include additional user details as needed
                new Claim("RoleName", user.RoleName) // Include role details
            };

            claims.Add(new Claim(ClaimTypes.Role, user.RoleName));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:ExpirationInMinutes"])),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool UserExists(int id)
        {
            return (_context.Users?.Any(e => e.UserId == id)).GetValueOrDefault();
        }


        [HttpGet("GetUserByUsername/{username}")]
        //[Authorize(Roles = "Admin")] // You can remove this attribute if you want to allow non-admins to access this endpoint
        public async Task<ActionResult<User>> GetUserByUsername(string username)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.UserName == username);

            if (user == null)
            {
                return NotFound($"User with username '{username}' not found.");
            }

            return user;
        }


        //[HttpGet("GetUserByEmail/{email}")]
        //public async Task<ActionResult<User>> GetUserByEmail(string email)
        //{
        //    var user = await _context.Users
        //        .FirstOrDefaultAsync(u => u.Email == email);

        //    if (user == null)
        //    {
        //        return NotFound($"User with email '{email}' not found.");
        //    }

        //    return user;
        //}

        //[Authorize]
        [CustomAuthorize("Admin", "Super Admin","User")]
        [HttpGet("GetUserByEmail/{email}")]
        public async Task<ActionResult<UserDetailsDto>> GetUserByEmail(string email)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                return NotFound($"User with email '{email}' not found.");
            }

            var userDetailsDto = new UserDetailsDto
            {
                UserId = user.UserId,
                UserName = user.UserName,
                FullName = user.FullName,
                Email = user.Email,                
                Mobile = user.Mobile            

            };

            return userDetailsDto;
        }


        private string HashPassword(string password)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));

                return ByteArrayToHexString(hashedBytes);
            }
        }

        private string ByteArrayToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }
    }


    public class LoginRequest
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
    }

    public class UserWithRoleDTO
    {
        public int UserId { get; set; }
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public string? RoleName { get; set; }
    }

    public class UserDetailsDto
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string Mobile { get; set; }
    }

    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, Inherited = true, AllowMultiple = true)]
    public class CustomAuthorizeAttribute : AuthorizeAttribute
    {
        public CustomAuthorizeAttribute(params string[] roles) : base()
        {
            Roles = string.Join(",", roles);
        }
    }

}
