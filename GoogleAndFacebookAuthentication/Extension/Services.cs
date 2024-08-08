using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Facebook;
namespace GoogleAndFacebookAuthentication.Extensions
{
    public static class Services
    {
        public static void ConfigAuthentication(this IServiceCollection services , IConfiguration configuration) 
        {
            //var GoogleSettings = configuration.GetSection("Google");

            services.AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = "Application";
                options.DefaultAuthenticateScheme = "SecondToken";
            })
            .AddCookie("Application")
            .AddCookie("External")
            .AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
            {
                options.ClientId = configuration.GetSection("Google:ClientId").Value!;
                options.ClientSecret = configuration.GetSection("Google:ClientSecret").Value!;
            })
            .AddFacebook(FacebookDefaults.AuthenticationScheme, options =>
            {
                options.AppId = configuration.GetSection("FaceBook:AppId").Value!;
                options.AppSecret = configuration.GetSection("FaceBook:AppSecret").Value!;
            })
            ;
        }
    
        
        
    }
}
