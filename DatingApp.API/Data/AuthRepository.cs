using System;
using System.Linq;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _Context;
        public AuthRepository(DataContext context)
        {
            _Context = context;

        }

        public async Task<user> Register(user user, string password)
        {
            byte[] passwordHash, passwordSalt;
            CreatePasswordHash(password, out passwordHash, out passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            await _Context.Users.AddAsync(user);
            await _Context.SaveChangesAsync();
            return user;

        }

        public async Task<user> Login(string username, string password)
        {
            var user =  await  _Context.Users.FirstOrDefaultAsync(x=>x.Username==username);
           
            if(user==null)
            {
                return null;
            }

           if(!VerifyPasswordHash( password, user.PasswordHash,user.PasswordSalt))
           {
               return null;
           }
           return user;

        }

         private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (computedHash[i] != passwordHash[i])
                        return false;

                }
                return true;
            }

        }
        public async Task<bool> UserExists(string username)
        {
             if (await _Context.Users.AnyAsync(x=>x.Username==username))
           return true;

           return false;
        }

    
    }
}