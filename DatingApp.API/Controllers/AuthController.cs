using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace DatingApp.API.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
         public IAuthRepository _authRepository;
         public IConfiguration _config;
        public AuthController(IAuthRepository _authRepository,IConfiguration config)
        {
            this._authRepository = _authRepository;
            _config = config;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto)
        {
            //TODO: Validate User
          
          userForRegisterDto.Username=userForRegisterDto.Username.ToLower();

            if(await _authRepository.UserExists(userForRegisterDto.Username))
            return BadRequest("This user already exists.");

           var userToCreate = new user{
            Username=userForRegisterDto.Username
           };

            var CreatedUser= await _authRepository.Register(userToCreate,userForRegisterDto.Password);
            return StatusCode(201);
        }

         [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto)
        {
            var userFromRepo= await _authRepository.Login(userForLoginDto.UserName.ToLower(),userForLoginDto.Password);
            if(userFromRepo==null)
            return Unauthorized();

            //We are building a an authentication token to return to the user
            var claims=new[]
            {
                new Claim(ClaimTypes.NameIdentifier,userFromRepo.Id.ToString()),
                 new Claim(ClaimTypes.Name,userFromRepo.Username)
            };

            var key=new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));
            var creds=new SigningCredentials(key,SecurityAlgorithms.HmacSha512Signature);
            var tokenDescriptor=new SecurityTokenDescriptor
            {
                Subject=new ClaimsIdentity(claims),
                Expires= DateTime.Now.AddDays(1),
                SigningCredentials=creds

            };

            var tokenHandler= new JwtSecurityTokenHandler();
            var token=tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new {
                token=tokenHandler.WriteToken(token)

            });
        }
    }
}