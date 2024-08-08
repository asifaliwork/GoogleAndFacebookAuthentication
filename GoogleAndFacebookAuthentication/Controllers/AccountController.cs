using GoogleAndFacebookAuthentication.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using GoogleAndFacebookAuthentication.Models.Account;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Facebook;
namespace GoogleAndFacebookAuthentication.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _db;
        SignInManager<ApplicationUser> _signInManager;
        UserManager<ApplicationUser> _userManager;
        RoleManager<IdentityRole> _roleManager;

        public AccountController(ApplicationDbContext db,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
        {
            this._db = db;
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            var aa = _db.Users.ToList();
            return View(aa);
        }

        public IActionResult Login()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> login(LoginModel loginModel)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(loginModel.Email!, loginModel.Password!, loginModel.RememberMe, false);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(loginModel.Email!);
                    if (_signInManager.IsSignedIn(User))
                    {
                        return RedirectToAction("Index");
                    }
                    return RedirectToAction("Index");
                }
            }
            ModelState.AddModelError("", "Invalid Login attempt");
            return View(loginModel);
        }
        public IActionResult Register()
        {
            var model = new RegisterModel();
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel registerModel)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerModel.EmailAddress,
                    Email = registerModel.EmailAddress,
                    NormalizedUserName = registerModel.EmailAddress!.ToUpper(),
                    NormalizedEmail = registerModel.EmailAddress.ToUpper(),
                };

                var result = await _userManager.CreateAsync(user, registerModel.Password!);
                if (result.Succeeded)
                {
                    var role = await _roleManager.FindByNameAsync("User");
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return RedirectToAction("Index");
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }
            }
            return View();
        }

        public IActionResult ExternalLogin()
        {
            return new ChallengeResult(
                GoogleDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("GoogleResponse", "Account")
                });
        }
        public async Task<IActionResult> GoogleResponse()
        {

            var authenticateResult = await HttpContext.AuthenticateAsync("Identity.External");
            if (!authenticateResult.Succeeded)
                return BadRequest();

            if (authenticateResult.Principal.Identities.ToList()[0].AuthenticationType!.ToLower() == "google")
            {

                if (authenticateResult.Principal != null)
                {

                    var googleAccountId = authenticateResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    var claimsIdentity = new ClaimsIdentity("Application");
                    if (authenticateResult.Principal != null)
                    {
                        var name = authenticateResult.Principal.FindFirst(ClaimTypes.Name)?.Value;
                        var email = authenticateResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
                        string userName = email ?? name.Replace(" ", ".").ToLower();

                        var loginModel = new ApplicationUser
                        {
                            UserName = userName,
                            Name = name,
                            Email = email,
                            
                        };
                    var result = await _userManager.CreateAsync(loginModel, "Asd123@");
                        if (result.Succeeded)
                        {
                            var role = await _roleManager.FindByNameAsync("User");
                            await _signInManager.SignInAsync(loginModel, isPersistent: false);
                            return RedirectToAction("Index");
                        }
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        claimsIdentity.AddClaim(authenticateResult.Principal.FindFirst(ClaimTypes.Name)!);
                        claimsIdentity.AddClaim(authenticateResult.Principal.FindFirst(ClaimTypes.Email)!);
                        await HttpContext.SignInAsync("Application", new ClaimsPrincipal(claimsIdentity));
                        return RedirectToAction("Index", "Account");
                    }
                }
            }
            return RedirectToAction("Index", "Home");
        }

        public IActionResult FaceBookLogin()
        {
            return new ChallengeResult(
                FacebookDefaults.AuthenticationScheme,
                new AuthenticationProperties
                {
                    RedirectUri = Url.Action("FaceBookResponse", "Account")
                });
        }

        public async Task<IActionResult> FaceBookResponse()
        {

            var authenticateResult = await HttpContext.AuthenticateAsync("Identity.External");
            if (!authenticateResult.Succeeded)
                return BadRequest();

            if (authenticateResult.Principal.Identities.ToList()[0].AuthenticationType!.ToLower() == "facebook")
            {

                if (authenticateResult.Principal != null)
                {

                    var googleAccountId = authenticateResult.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    var claimsIdentity = new ClaimsIdentity("Application");
                    if (authenticateResult.Principal != null)
                    {
                        if (ModelState.IsValid)
                        {
                            var name = authenticateResult.Principal.FindFirst(ClaimTypes.Name)?.Value;
                            var email = authenticateResult.Principal.FindFirst(ClaimTypes.Email)?.Value;
                            var mobileNumber = authenticateResult.Principal.FindFirst(ClaimTypes.MobilePhone)?.Value;                            
                            string userName = email ?? name.Replace(" ", ".").ToLower();
                           
                            var loginModel = new ApplicationUser
                            {
                                UserName = userName, 
                                Name = name,
                                PhoneNumber = mobileNumber,                              
                            };

                            var result = await _userManager.CreateAsync(loginModel, "Asd123@");
                            if (result.Succeeded)
                            {
                                var role = await _roleManager.FindByNameAsync("User");
                                await _signInManager.SignInAsync(loginModel, isPersistent: false);
                                return RedirectToAction("Index");
                            }
                            foreach (var error in result.Errors)
                            {
                                ModelState.AddModelError("", error.Description);
                            }

                        }

                        var details = authenticateResult.Principal.Claims.ToList();
                        claimsIdentity.AddClaim(authenticateResult.Principal.FindFirst(ClaimTypes.Name)!);
                       // claimsIdentity.AddClaim(authenticateResult.Principal.FindFirst(ClaimTypes.Email));
                       // claimsIdentity.AddClaim(authenticateResult.Principal.FindFirst(ClaimTypes.MobilePhone));
                        await HttpContext.SignInAsync("Application", new ClaimsPrincipal(claimsIdentity));
                        return RedirectToAction("Index", "Account");
                    }
                }
            }
            return RedirectToAction("Index", "Home");
        }
       
        public async Task<IActionResult> SignOutFromGoogleLogin()
        {
            if (HttpContext.Request.Cookies.Count > 0)
            {
                var siteCookies = HttpContext.Request.Cookies.Where(c => c.Key.Contains(".AspNetCore.") || c.Key.Contains("Microsoft.Authentication"));
                foreach (var cookie in siteCookies)
                {
                    Response.Cookies.Delete(cookie.Key);
                }
            }
            await HttpContext.SignOutAsync("Identity.External");
           return RedirectToAction("Login", "Account");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

    }
}
