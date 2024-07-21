using FreshFlow.Models;
using FreshFlow.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration.EnvironmentVariables;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FreshFlow.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
       
      {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly SignInManager<IdentityUser>_signInManager;

        public AuthenticationController(UserManager<IdentityUser> userManager,
             RoleManager<IdentityRole> roleManager, IConfiguration configuration,IEmailService emailservice, SignInManager<IdentityUser> signInManager)
        {
             
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration=  configuration;
            _emailService = emailservice;
            _signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register( [FromBody]RegisterUser registerUser, string role)
        {
            //Check if user exist
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if(userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User Already exists!" });
            }

            //Add user to db
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,
                TwoFactorEnabled=true
            };
            if   ( await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                                       new Response { Status = "Error", Message = "User failed to create!" });
                }
                //add role to the user 
                await _userManager.AddToRoleAsync(user,role);

                // Add Token to verify the email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email },Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Confirmation emial link", confirmationLink!);
                _emailService.SendEmail(message);
                 

                return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "Error", Message = $"User created & Email Sent to {user.Email} successfully" });
              
            }
           
           else
            {

                return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "This role does not exist" });
            }
            //Assign role
        }


        /*  [HttpGet]
          public async Task<IActionResult> TestEmail()
          {
              var message =
                     (new string[] { "sisekelozimu@gmail.com" }, "Test", "<h1>Subscribe to my channel</h1>");

              _emailService.SendEmail(message);

              return StatusCode(StatusCodes.Status200OK,
                  new Response { Status = "Success", Message = "Email Sent Successfully" });

          }*/
        [HttpGet("ConfirmEmail")]
        public async Task <IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { Status = "Error", Message = "This user does not exist " });
        }


        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {// check user and password
            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false,true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);


                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"We have sent an otp to your email{user.Email}" });
            }
            if (user!= null && await _userManager.CheckPasswordAsync(user,loginModel.Password))
            {

                // claimlist creation
                var authClaims = new List<Claim> 
                {  
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                //add roles to list
                var userRole = await _userManager.GetRolesAsync(user);
                 foreach (var role in userRole)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
               

                var jwtTokens = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtTokens),
                    expiration = jwtTokens.ValidTo
                });
    


                }
            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]
        public async Task <IActionResult> LoginWithOTP(string code,string username)
            
        {
            var user = await _userManager.FindByNameAsync( username);
           var signIn = await  _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if(signIn.Succeeded)
            {

                if (user != null )
                {

                    // claimlist creation
                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                    //add roles to list
                    var userRole = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRole)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }


                    var jwtTokens = GetToken(authClaims);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtTokens),
                        expiration = jwtTokens.ValidTo
                    });

                    // returning the token

                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
                   new Response { Status = "Success", Message = $"Invalid Code" });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
         public async Task<IActionResult> ForgotPassword([Required]string email)
        {
            var  user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user); 
                var forgotPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot passowrd  link", forgotPasswordlink!);

                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status="Success",Message=$"Password Changed request is sent on email {user.Email}Please open your email & click link"});
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                   new Response { Status = "Error", Message = $"Could not send link to email, please try again " });
        }

        [HttpGet("reset-password")]
          public async Task<IActionResult> ResetPassword(string token, string email)
          {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new

            {
                          
                model
            });

          }
        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token,resetPassword.Password);
                if (!resetPassResult.Succeeded) 
                { 
                    foreach(var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }

                
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password has been Changed" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                   new Response { Status = "Error", Message = $"Could not send link to email, please try again " });
        }
        private JwtSecurityToken GetToken(List<Claim>authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:Validaudience"],
                audience: _configuration["JWT:ValidAudience"],
                expires:DateTime.Now.AddHours(3),
                claims:authClaims,
                signingCredentials: new SigningCredentials(authSigninKey,SecurityAlgorithms.HmacSha256)
            );
            return token;

        }
    }
}
