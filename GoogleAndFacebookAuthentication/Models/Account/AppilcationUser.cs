using Microsoft.AspNetCore.Identity;

namespace GoogleAndFacebookAuthentication.Models.Account
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
