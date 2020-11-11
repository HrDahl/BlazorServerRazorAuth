using BlazorServerAuthentication.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorServerAuthentication
{
    public class _HostAuthModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public _HostAuthModel(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public async Task<IActionResult> OnGetLogout()
        {
            await HttpContext.SignOutAsync("Cookies");
            await _signInManager.SignOutAsync();
            return LocalRedirect(Url.Content("~/"));
        }

        public async Task<IActionResult> OnGetLogin(string username, string password, string redirectUri = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync("Cookies");
            redirectUri = redirectUri ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                if (string.IsNullOrEmpty(username))
                {
                    username = "MrDahl";
                    password = "Ayni2013";
                }
                
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(username, password, true, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, username)
                    };
                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        RedirectUri = this.Request.Host.Value
                    };
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);                    
                }
                //if (result.RequiresTwoFactor)
                //{
                //    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = true });
                //}
                //if (result.IsLockedOut)
                //{
                //    return RedirectToPage("./Lockout");
                //}
                //else
                //{
                //    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                //    return Page();
                //}
            }
            return LocalRedirect(redirectUri);
        }
    }
}
