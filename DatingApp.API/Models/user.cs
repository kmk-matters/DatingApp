namespace DatingApp.API.Models
{
    public class user
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public byte[] PasswordHash{get;set;}
        public byte[] PasswordSalt{get;set;}

    }
}